#!/usr/bin/env python3
"""
Read-only Zclassic chain-history auditor for shielded-pool and block-size risks.

This script calls only read-only RPCs through direct HTTP JSON-RPC by default:
  getblockchaininfo, gettxoutsetinfo, getblock

It does not create transactions, does not submit blocks, and does not modify the
node or datadir. Use --full for an exhaustive block walk; the default stride is
sampling and cannot prove absence of a transient historical negative pool.

ZIP-209 / CR-01 deployment prerequisite & check
-----------------------------------------------
This is the prerequisite validation for the ZIP-209 shielded turnstile (mainnet)
and the CR-01 IBD-validation fix. Run it (read-only) on a fully-synced mainnet
node BEFORE building/running a ZIP-209 binary or re-validating with `-reindex`:

    python3 scripts/audit-mainnet-history.py --full --supply-check

Expected on a healthy chain:
  * "negative pool events found in scan: 0" — no block ever drove a Sprout or
    Sapling value-pool balance negative, so enabling ZIP-209 (and a reindex)
    will NOT reject the existing chain.
  * supply "status=OK" — observable supply does not exceed expected issuance.

It also reports the Sprout value-pool balance: this MUST equal the compiled
ZIP-209 checkpoint (CMainParams::nSproutValuePoolCheckpointBalance), otherwise a
ZIP-209 node aborts on the FallbackSproutValuePoolBalance assert at startup. See
doc/zip209-cr01-testing.md for the full tester checklist.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import subprocess
import sys
import time
from decimal import Decimal, ROUND_DOWN
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

COIN = 100_000_000
INITIAL_SUBSIDY_ZAT = int(Decimal("12.5") * COIN)

MAINNET_OVERWINTER_SAPLING_HEIGHT = 476_969
MAINNET_BUBBLES_HEIGHT = 585_318
MAINNET_DIFFADJ_HEIGHT = 585_322
MAINNET_BUTTERCUP_HEIGHT = 707_000
PRE_BUTTERCUP_HALVING_INTERVAL = 840_000
POST_BUTTERCUP_HALVING_INTERVAL = PRE_BUTTERCUP_HALVING_INTERVAL * 2
SUBSIDY_SLOW_START_INTERVAL = 2
SUBSIDY_SLOW_START_SHIFT = SUBSIDY_SLOW_START_INTERVAL // 2
DEFAULT_MAINNET_RPC_PORT = 8023
DEFAULT_TEST_RPC_PORT = 18023


def parse_args() -> argparse.Namespace:
    default_cli = Path("src/zclassic-cli")
    parser = argparse.ArgumentParser(
        description="Read-only shielded-pool and block-size audit against a local zclassicd node."
    )
    parser.add_argument("--use-cli", action="store_true", help="Use zclassic-cli subprocess calls instead of direct HTTP RPC.")
    parser.add_argument("--cli", default=str(default_cli if default_cli.exists() else "zclassic-cli"))
    parser.add_argument("--datadir", help="Optional zclassic datadir.")
    parser.add_argument(
        "--cli-arg",
        action="append",
        default=[],
        help="Extra zclassic-cli-compatible option, e.g. --cli-arg=-rpcuser=... --cli-arg=-rpcpassword=...",
    )
    parser.add_argument("--rpcconnect", help="RPC host for direct HTTP mode. Default: zclassic.conf or 127.0.0.1.")
    parser.add_argument("--rpcport", type=int, help="RPC port for direct HTTP mode. Default: zclassic.conf or chain default.")
    parser.add_argument("--rpcuser", help="RPC username for direct HTTP mode.")
    parser.add_argument("--rpcpassword", help="RPC password for direct HTTP mode.")
    parser.add_argument("--rpccookiefile", help="RPC auth cookie path. Relative paths resolve under the network datadir.")
    parser.add_argument("--rpc-timeout", type=int, default=600, help="Direct HTTP RPC timeout in seconds.")
    parser.add_argument("--batch-size", type=int, default=250, help="getblock RPC calls per direct HTTP batch.")
    parser.add_argument("--allow-non-main", action="store_true", help="Allow testnet/regtest auditing.")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--end", type=int, help="Default: current tip height.")
    parser.add_argument("--stride", type=int, default=10_000, help="Block sampling stride. Use --full for stride 1.")
    parser.add_argument("--full", action="store_true", help="Scan every block height.")
    parser.add_argument("--extra-height", type=int, action="append", default=[], help="Additional height to force-scan.")
    parser.add_argument("--block-size-limit", type=int, default=200_000, help="Expected MAX_BLOCK_SIZE threshold.")
    parser.add_argument("--skip-txoutset", action="store_true", help="Skip gettxoutsetinfo and supply comparison.")
    parser.add_argument("--supply-check", action="store_true", help="Compute expected mainnet issuance and compare observable supply.")
    parser.add_argument("--json-output", help="Write full audit result to this JSON file.")
    parser.add_argument("--progress-every", type=int, default=1_000, help="Progress interval in checked blocks; 0 disables.")
    return parser.parse_args()


class Cli:
    def __init__(self, binary: str, datadir: Optional[str], extra_args: List[str]):
        self.base = [binary]
        if datadir:
            self.base.append(f"-datadir={datadir}")
        self.base.extend(extra_args)
        self.mode = "zclassic-cli subprocess"

    def call(self, method: str, *params: Any) -> Any:
        cmd = self.base + [method] + [cli_arg(param) for param in params]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            raise RuntimeError(
                "zclassic-cli failed\n"
                f"command: {' '.join(cmd)}\n"
                f"stderr: {proc.stderr.strip()}\n"
                f"stdout: {proc.stdout.strip()}"
            )
        out = proc.stdout.strip()
        if not out:
            return None
        return json.loads(out, parse_float=Decimal)

    def batch(self, calls: List[Tuple[str, List[Any]]]) -> List[Any]:
        return [self.call(method, *params) for method, params in calls]


def cli_arg(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


class HttpRpc:
    def __init__(self, host: str, port: int, auth: str, timeout: int):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.auth_header = "Basic " + base64.b64encode(auth.encode("utf8")).decode("ascii")
        self.conn = http.client.HTTPConnection(host, port, timeout=timeout)
        self.next_id = 0
        self.mode = f"direct HTTP JSON-RPC batch ({host}:{port})"

    def _next_id(self) -> int:
        self.next_id += 1
        return self.next_id

    def _request_once(self, body: str) -> Any:
        headers = {
            "Host": self.host,
            "User-Agent": "zclassic-audit-mainnet-history/1.0",
            "Authorization": self.auth_header,
            "Content-Type": "application/json",
        }
        self.conn.request("POST", "/", body=body, headers=headers)
        response = self.conn.getresponse()
        raw = response.read().decode("utf8")
        if response.status == 401:
            raise RuntimeError("RPC authorization failed; check rpcuser/rpcpassword or the auth cookie.")
        if not raw:
            raise RuntimeError(f"RPC server returned empty HTTP {response.status} {response.reason}")
        try:
            parsed = json.loads(raw, parse_float=Decimal)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"RPC server returned non-JSON HTTP {response.status} {response.reason}: {raw[:200]}") from exc
        if response.status >= 400 and not _rpc_response_has_error(parsed):
            raise RuntimeError(f"RPC server returned HTTP {response.status} {response.reason}: {raw[:200]}")
        return parsed

    def _request(self, payload: Any) -> Any:
        body = json.dumps(payload)
        retry_errors = (
            http.client.BadStatusLine,
            http.client.CannotSendRequest,
            http.client.RemoteDisconnected,
            http.client.ResponseNotReady,
            BrokenPipeError,
            ConnectionResetError,
        )
        for attempt in range(2):
            try:
                return self._request_once(body)
            except retry_errors:
                self.conn.close()
                self.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
                if attempt:
                    raise
            except OSError as exc:
                raise RuntimeError(f"could not connect to RPC server at {self.host}:{self.port}: {exc}") from exc
        raise RuntimeError("unreachable RPC retry state")

    def call(self, method: str, *params: Any) -> Any:
        req_id = self._next_id()
        payload = {"version": "1.1", "method": method, "params": list(params), "id": req_id}
        response = self._request(payload)
        if not isinstance(response, dict):
            raise RuntimeError(f"RPC {method} returned unexpected batch response")
        _raise_for_rpc_error(method, response)
        if "result" not in response:
            raise RuntimeError(f"RPC {method} response is missing result")
        return response["result"]

    def batch(self, calls: List[Tuple[str, List[Any]]]) -> List[Any]:
        if not calls:
            return []
        id_to_label: Dict[int, str] = {}
        payload = []
        order = []
        for method, params in calls:
            req_id = self._next_id()
            id_to_label[req_id] = f"{method} {params}"
            order.append(req_id)
            payload.append({"version": "1.1", "method": method, "params": params, "id": req_id})
        response = self._request(payload)
        if not isinstance(response, list):
            raise RuntimeError(f"RPC batch returned non-list response: {response!r}")

        by_id: Dict[int, Dict[str, Any]] = {}
        for item in response:
            if not isinstance(item, dict) or "id" not in item:
                raise RuntimeError(f"RPC batch returned malformed item: {item!r}")
            by_id[int(item["id"])] = item

        results = []
        for req_id in order:
            item = by_id.get(req_id)
            if item is None:
                raise RuntimeError(f"RPC batch response is missing id {req_id}")
            _raise_for_rpc_error(id_to_label[req_id], item)
            if "result" not in item:
                raise RuntimeError(f"RPC batch response for {id_to_label[req_id]} is missing result")
            results.append(item["result"])
        return results


def _rpc_response_has_error(response: Any) -> bool:
    if isinstance(response, dict):
        return "error" in response
    if isinstance(response, list):
        return any(isinstance(item, dict) and "error" in item for item in response)
    return False


def _raise_for_rpc_error(label: str, response: Dict[str, Any]) -> None:
    error = response.get("error")
    if error is None:
        return
    if isinstance(error, dict):
        message = error.get("message", error)
        code = error.get("code")
        raise RuntimeError(f"RPC {label} failed with code {code}: {message}")
    raise RuntimeError(f"RPC {label} failed: {error}")


def parse_dash_options(args: Iterable[str]) -> Dict[str, str]:
    options: Dict[str, str] = {}
    for raw in args:
        if not raw.startswith("-"):
            continue
        item = raw.lstrip("-")
        if not item:
            continue
        if "=" in item:
            key, value = item.split("=", 1)
            options[key] = value
        else:
            options[item] = "1"
    return options


def truthy(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.lower() not in ("", "0", "false", "no")


def read_config_file(path: Path) -> Dict[str, str]:
    config: Dict[str, str] = {}
    if not path.exists():
        return config
    for raw_line in path.read_text(errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";") or line.startswith("["):
            continue
        for marker in (" #", "\t#", " ;", "\t;"):
            if marker in line:
                line = line.split(marker, 1)[0].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        config[key.strip()] = value.strip()
    return config


def default_datadir() -> Path:
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library/Application Support/ZClassic"
    if sys.platform.startswith("win"):
        return home / "AppData/Roaming/ZClassic"
    return home / ".zclassic"


def network_from_options(options: Dict[str, str], config: Dict[str, str]) -> str:
    if truthy(options.get("regtest")) or truthy(config.get("regtest")):
        return "regtest"
    if truthy(options.get("testnet")) or truthy(config.get("testnet")):
        return "testnet"
    return "main"


def network_datadir(base_datadir: Path, network: str) -> Path:
    if network == "testnet":
        return base_datadir / "testnet3"
    if network == "regtest":
        return base_datadir / "regtest"
    return base_datadir


def resolve_rpc_settings(args: argparse.Namespace) -> Tuple[str, int, str]:
    cli_options = parse_dash_options(args.cli_arg)
    base_datadir = Path(args.datadir or cli_options.get("datadir") or default_datadir()).expanduser()

    conf_name = cli_options.get("conf", "zclassic.conf")
    conf_path = Path(conf_name).expanduser()
    if not conf_path.is_absolute():
        conf_path = base_datadir / conf_path
    config = read_config_file(conf_path)

    network = network_from_options(cli_options, config)
    rpc_host = args.rpcconnect or cli_options.get("rpcconnect") or config.get("rpcconnect") or "127.0.0.1"
    default_port = DEFAULT_TEST_RPC_PORT if network in ("testnet", "regtest") else DEFAULT_MAINNET_RPC_PORT
    rpc_port = int(args.rpcport or cli_options.get("rpcport") or config.get("rpcport") or default_port)

    rpc_user = args.rpcuser or cli_options.get("rpcuser") or config.get("rpcuser") or ""
    rpc_password = args.rpcpassword or cli_options.get("rpcpassword") or config.get("rpcpassword") or ""
    if rpc_password:
        return rpc_host, rpc_port, f"{rpc_user}:{rpc_password}"

    cookie_name = args.rpccookiefile or cli_options.get("rpccookiefile") or config.get("rpccookiefile") or ".cookie"
    cookie_path = Path(cookie_name).expanduser()
    if not cookie_path.is_absolute():
        cookie_path = network_datadir(base_datadir, network) / cookie_path
    if cookie_path.exists():
        cookie = cookie_path.read_text(errors="replace").strip()
        if cookie:
            return rpc_host, rpc_port, cookie

    raise RuntimeError(
        "Could not locate RPC credentials. Pass --rpcuser/--rpcpassword, "
        f"--rpccookiefile, --datadir, or use --use-cli. Tried cookie: {cookie_path}; config: {conf_path}"
    )


def make_rpc(args: argparse.Namespace) -> Any:
    if args.use_cli:
        return Cli(args.cli, args.datadir, args.cli_arg)
    host, port, auth = resolve_rpc_settings(args)
    return HttpRpc(host, port, auth, args.rpc_timeout)


def amount_to_zat(value: Any) -> int:
    dec = value if isinstance(value, Decimal) else Decimal(str(value))
    return int((dec * COIN).to_integral_value(rounding=ROUND_DOWN))


def cxx_div_toward_zero(a: int, b: int) -> int:
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b >= 0) else -q


def mainnet_block_subsidy_zat(height: int) -> int:
    n_subsidy = INITIAL_SUBSIDY_ZAT
    if height < SUBSIDY_SLOW_START_INTERVAL // 2:
        return (n_subsidy // SUBSIDY_SLOW_START_INTERVAL) * height
    if height < SUBSIDY_SLOW_START_INTERVAL:
        return (n_subsidy // SUBSIDY_SLOW_START_INTERVAL) * (height + 1)

    if height >= MAINNET_BUTTERCUP_HEIGHT:
        halvings = cxx_div_toward_zero(
            height - SUBSIDY_SLOW_START_SHIFT - MAINNET_BUTTERCUP_HEIGHT,
            POST_BUTTERCUP_HALVING_INTERVAL,
        ) + 3
        base = n_subsidy // 2
    else:
        halvings = (height - SUBSIDY_SLOW_START_SHIFT) // PRE_BUTTERCUP_HALVING_INTERVAL
        base = n_subsidy

    if halvings >= 64:
        return 0
    return base >> halvings


def expected_issued_zat_mainnet(tip_height: int) -> int:
    # Genesis coinbase is not counted here; mining starts at height 1.
    return sum(mainnet_block_subsidy_zat(h) for h in range(1, tip_height + 1))


def pool_map(block_or_info: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {pool.get("id"): pool for pool in block_or_info.get("valuePools", [])}


def pool_chain_value(pool: Dict[str, Any]) -> Optional[int]:
    if not pool.get("monitored", False):
        return None
    if "chainValueZat" not in pool:
        return None
    return int(pool["chainValueZat"])


def selected_heights(
    start: int,
    end: int,
    stride: int,
    extras: Iterable[int],
    include_mainnet_landmarks: bool,
) -> List[int]:
    heights = set()
    if stride <= 0:
        raise ValueError("stride must be positive")
    h = start
    while h <= end:
        heights.add(h)
        h += stride
    heights.add(end)
    for extra in extras:
        if start <= extra <= end:
            heights.add(extra)
    if include_mainnet_landmarks:
        for landmark in (
            MAINNET_OVERWINTER_SAPLING_HEIGHT - 1,
            MAINNET_OVERWINTER_SAPLING_HEIGHT,
            MAINNET_BUBBLES_HEIGHT,
            MAINNET_DIFFADJ_HEIGHT,
            MAINNET_BUTTERCUP_HEIGHT - 1,
            MAINNET_BUTTERCUP_HEIGHT,
        ):
            if start <= landmark <= end:
                heights.add(landmark)
    return sorted(heights)


def chunks(values: List[int], size: int) -> Iterable[List[int]]:
    if size <= 0:
        raise ValueError("batch size must be positive")
    for offset in range(0, len(values), size):
        yield values[offset : offset + size]


def scan_blocks(rpc: Any, heights: List[int], block_size_limit: int, progress_every: int, batch_size: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "blocks_checked": 0,
        "negative_pool_events": [],
        "unmonitored_pool_events": [],
        "oversized_blocks": [],
        "max_block_size": {"height": None, "hash": None, "size": 0},
        "pools": {
            "sprout": {"first_monitored": None, "first_nonzero_delta": None, "min": None, "max": None},
            "sapling": {"first_monitored": None, "first_nonzero_delta": None, "min": None, "max": None},
        },
    }
    started = time.time()
    total = len(heights)
    for batch_heights in chunks(heights, batch_size):
        calls = [("getblock", [str(height), True]) for height in batch_heights]
        blocks = rpc.batch(calls)
        for height, block in zip(batch_heights, blocks):
            result["blocks_checked"] += 1

            size = int(block.get("size", 0))
            if size > result["max_block_size"]["size"]:
                result["max_block_size"] = {"height": height, "hash": block.get("hash"), "size": size}
            if size > block_size_limit:
                result["oversized_blocks"].append({"height": height, "hash": block.get("hash"), "size": size})

            pools = pool_map(block)
            for pool_name in ("sprout", "sapling"):
                pool = pools.get(pool_name, {})
                chain_value = pool_chain_value(pool)
                stats = result["pools"][pool_name]
                if chain_value is None:
                    if len(result["unmonitored_pool_events"]) < 50:
                        result["unmonitored_pool_events"].append({"height": height, "pool": pool_name})
                    continue

                if stats["first_monitored"] is None:
                    stats["first_monitored"] = height
                stats["min"] = chain_value if stats["min"] is None else min(stats["min"], chain_value)
                stats["max"] = chain_value if stats["max"] is None else max(stats["max"], chain_value)
                if chain_value < 0:
                    result["negative_pool_events"].append(
                        {"height": height, "hash": block.get("hash"), "pool": pool_name, "chainValueZat": chain_value}
                    )
                if pool.get("valueDeltaZat") not in (None, 0, "0") and stats["first_nonzero_delta"] is None:
                    stats["first_nonzero_delta"] = {
                        "height": height,
                        "hash": block.get("hash"),
                        "valueDeltaZat": int(pool["valueDeltaZat"]),
                    }

            if progress_every and result["blocks_checked"] % progress_every == 0:
                elapsed = time.time() - started
                print(f"checked {result['blocks_checked']}/{total} selected heights in {elapsed:.1f}s", file=sys.stderr)

    return result


def print_summary(result: Dict[str, Any]) -> None:
    print("== Zclassic Read-Only Chain Audit ==")
    print(f"chain: {result['chain']}")
    print(f"tip: {result['tip_height']} {result['tip_hash']}")
    print(f"scan: start={result['scan']['start']} end={result['scan']['end']} stride={result['scan']['stride']} full={result['scan']['full']}")
    print(f"rpc: {result['scan'].get('rpc_mode')} batch_size={result['scan'].get('batch_size')}")
    print(f"selected heights checked: {result['scan']['blocks_checked']}")
    print()

    print("== Shielded Pools ==")
    for name, pool in result["tip_value_pools"].items():
        print(f"tip {name}: monitored={pool.get('monitored')} chainValueZat={pool.get('chainValueZat')}")
    print(f"negative pool events found in scan: {len(result['scan']['negative_pool_events'])}")
    if result["scan"]["negative_pool_events"]:
        for event in result["scan"]["negative_pool_events"][:10]:
            print(f"  NEGATIVE {event}")
    print(f"unmonitored pool samples: {len(result['scan']['unmonitored_pool_events'])}")
    for name, stats in result["scan"]["pools"].items():
        print(f"{name}: first_monitored={stats['first_monitored']} min={stats['min']} max={stats['max']} first_nonzero_delta={stats['first_nonzero_delta']}")
    print()

    print("== Block Size ==")
    print(f"max observed block size: {result['scan']['max_block_size']}")
    print(f"blocks over configured limit: {len(result['scan']['oversized_blocks'])}")
    for event in result["scan"]["oversized_blocks"][:10]:
        print(f"  OVERSIZE {event}")
    print()

    if "supply" in result:
        print("== Observable Supply ==")
        supply = result["supply"]
        print(f"transparent_utxo_zat={supply.get('transparent_utxo_zat')}")
        print(f"monitored_pool_sum_zat={supply.get('monitored_pool_sum_zat')}")
        print(f"observable_zat={supply.get('observable_zat')}")
        print(f"expected_issued_zat={supply.get('expected_issued_zat')}")
        print(f"observable_minus_expected_zat={supply.get('observable_minus_expected_zat')}")
        print(f"status={supply.get('status')}")
        print()

    print("== Warnings ==")
    for warning in result["warnings"]:
        print(f"- {warning}")


def main() -> int:
    args = parse_args()
    if args.full:
        args.stride = 1
    if args.start < 0:
        raise SystemExit("--start must be non-negative")

    rpc = make_rpc(args)
    info = rpc.call("getblockchaininfo")
    chain = info["chain"]
    tip_height = int(info["blocks"])
    tip_hash = info["bestblockhash"]
    end = tip_height if args.end is None else min(args.end, tip_height)
    if end < args.start:
        raise SystemExit("--end must be >= --start")
    if chain != "main" and not args.allow_non_main:
        raise SystemExit(f"Refusing to audit non-main chain {chain!r}; pass --allow-non-main if intentional.")

    warnings: List[str] = []
    if args.stride != 1:
        warnings.append("Scan is sampled, not exhaustive. Use --full to prove absence across every block height.")
    if info.get("pruned"):
        warnings.append("Node is pruned; historical getblock calls may fail for old blocks.")
    if Decimal(str(info.get("verificationprogress", "0"))) < Decimal("0.999"):
        warnings.append("Node verificationprogress is below 0.999; audit may be against an incomplete chain.")

    heights = selected_heights(
        args.start,
        end,
        args.stride,
        args.extra_height,
        include_mainnet_landmarks=(chain == "main"),
    )
    scan = scan_blocks(rpc, heights, args.block_size_limit, args.progress_every, args.batch_size)
    scan.update(
        {
            "start": args.start,
            "end": end,
            "stride": args.stride,
            "full": args.stride == 1,
            "rpc_mode": rpc.mode,
            "batch_size": args.batch_size,
        }
    )

    tip_pools = pool_map(info)
    result: Dict[str, Any] = {
        "chain": chain,
        "tip_height": tip_height,
        "tip_hash": tip_hash,
        "verificationprogress": str(info.get("verificationprogress")),
        "pruned": info.get("pruned"),
        "tip_value_pools": tip_pools,
        "scan": scan,
        "warnings": warnings,
    }

    if not args.skip_txoutset:
        txoutset = rpc.call("gettxoutsetinfo")
        result["txoutset"] = txoutset
        if args.supply_check:
            if chain != "main":
                warnings.append("Supply schedule comparison is implemented only for mainnet params.")
            else:
                transparent = amount_to_zat(txoutset["total_amount"])
                monitored_pool_values = []
                unmonitored_tip_pools = []
                for name in ("sprout", "sapling"):
                    value = pool_chain_value(tip_pools.get(name, {}))
                    if value is None:
                        unmonitored_tip_pools.append(name)
                    else:
                        monitored_pool_values.append(value)
                expected = expected_issued_zat_mainnet(tip_height)
                observable = transparent + sum(monitored_pool_values)
                status = "OK: observable supply does not exceed expected issuance"
                if observable > expected:
                    status = "ALERT: observable supply exceeds expected issuance"
                if unmonitored_tip_pools:
                    status += f"; incomplete because unmonitored tip pools: {', '.join(unmonitored_tip_pools)}"
                result["supply"] = {
                    "transparent_utxo_zat": transparent,
                    "monitored_pool_sum_zat": sum(monitored_pool_values),
                    "observable_zat": observable,
                    "expected_issued_zat": expected,
                    "observable_minus_expected_zat": observable - expected,
                    "status": status,
                }

    print_summary(result)
    if args.json_output:
        out_path = Path(args.json_output)
        out_path.write_text(json.dumps(result, indent=2, default=str) + "\n")
        print(f"\nWrote JSON report: {out_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        raise SystemExit(130)
