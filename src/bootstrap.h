// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BOOTSTRAP_H
#define BITCOIN_BOOTSTRAP_H

#include "protocol.h"
#include "streams.h"

#include <stdint.h>
#include <string>

#include <boost/filesystem/path.hpp>

class CNode;

static const uint32_t BOOTSTRAP_SNAPSHOT_CHUNK_SIZE = 512 * 1024;
static const uint32_t BOOTSTRAP_SNAPSHOT_MAX_CHUNK_SIZE = 512 * 1024;

bool BootstrapSnapshotPathsExist(const boost::filesystem::path& root);
bool IsBootstrapFreshChainDatadir(const boost::filesystem::path& data_dir, std::string& error);
bool ImportBootstrapDatadir(const boost::filesystem::path& source_root,
                            const boost::filesystem::path& data_dir,
                            bool force_backup,
                            std::string& error);
bool BootstrapFromPeer(const std::string& peer,
                       const boost::filesystem::path& data_dir,
                       std::string& error);

bool GetBootstrapSnapshotManifest(CBootstrapSnapshotManifest& manifest, std::string& error);
bool PreflightBootstrapSnapshotService(std::string& error);
bool ReadBootstrapSnapshotChunk(const CBootstrapSnapshotChunkRequest& request,
                                CBootstrapSnapshotChunk& chunk,
                                std::string& error);
bool ValidateBootstrapSnapshotManifest(const CBootstrapSnapshotManifest& manifest, std::string& error);
bool EnqueueBootstrapSnapshotChunkRequest(CNode* pfrom,
                                          const CBootstrapSnapshotChunkRequest& request,
                                          std::string& error);
bool SendQueuedBootstrapSnapshotChunk(CNode* pto);

bool BuildBootstrapNetworkMessage(const char* command,
                                  const CDataStream& payload,
                                  CSerializeData& message,
                                  std::string& error);
bool DecodeBootstrapNetworkMessage(const CSerializeData& message,
                                   std::string& command,
                                   CDataStream& payload,
                                   std::string& error);

#endif // BITCOIN_BOOTSTRAP_H
