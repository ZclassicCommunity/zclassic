// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "clientversion.h"
#include "embeddedtor.h"
#include "rpc/server.h"
#include "init.h"
#include "main.h"
#include "noui.h"
#include "scheduler.h"
#include "util.h"
#include "httpserver.h"
#include "httprpc.h"

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <windows.h>
#include <shellapi.h>
#endif

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include <stdio.h>

#include <fstream>
#include <iostream>


/* Introduction text for doxygen: */

/*! \mainpage Developer documentation
 *
 * \section intro_sec Introduction
 *
 * This is the developer documentation of the reference client for an experimental new digital currency called Bitcoin (https://www.bitcoin.org/),
 * which enables instant payments to anyone, anywhere in the world. Bitcoin uses peer-to-peer technology to operate
 * with no central authority: managing transactions and issuing money are carried out collectively by the network.
 *
 * The software is a community-driven open source project, released under the MIT license.
 *
 * \section Navigation
 * Use the buttons <code>Namespaces</code>, <code>Classes</code> or <code>Files</code> at the top of the page to start navigating the code.
 */

static bool fDaemon;

void WaitForShutdown(boost::thread_group* threadGroup)
{
    bool fShutdown = ShutdownRequested();
    // Tell the main threads to shutdown.
    while (!fShutdown)
    {
        MilliSleep(200);
        fShutdown = ShutdownRequested();
    }
    if (threadGroup)
    {
        Interrupt(*threadGroup);
        threadGroup->join_all();
    }
}


//////////////////////////////////////////////////////////////////////////////
//
// Start
//
/** Create `dir` if missing. Prints one clear error line naming the path and returns false on failure. */
static bool EnsureDirectoryExists(const boost::filesystem::path& dir, const char* what)
{
    if (dir.empty())
        return true; // a missing -datadir is reported by the caller
    boost::system::error_code ec;
    if (boost::filesystem::is_directory(dir, ec))
        return true;
    ec.clear();
    boost::filesystem::create_directories(dir, ec);
    if (ec || !boost::filesystem::is_directory(dir, ec)) {
        fprintf(stderr, "Error: Cannot create the %s \"%s\": %s\n", what, dir.string().c_str(),
                ec ? ec.message().c_str() : "not a directory");
        return false;
    }
    return true;
}

bool AppInit(int argc, char* argv[])
{
    boost::thread_group threadGroup;
    CScheduler scheduler;

    bool fRet = false;

    //
    // Parameters
    //
    ParseParameters(argc, argv);

    // Process help and version before taking care about datadir
    if (mapArgs.count("-?") || mapArgs.count("-h") ||  mapArgs.count("-help") || mapArgs.count("-version"))
    {
        std::string strUsage = _("ZClassic Daemon") + " " + _("version") + " " + FormatFullVersion() + "\n" + PrivacyInfo();

        if (mapArgs.count("-version"))
        {
            strUsage += LicenseInfo();
        }
        else
        {
            strUsage += "\n" + _("Usage:") + "\n" +
                  "  zclassicd [options]                     " + _("Start ZClassic Daemon") + "\n";

            strUsage += "\n" + HelpMessage(HMM_BITCOIND);
        }

        fprintf(stdout, "%s", strUsage.c_str());
        return true;
    }

    try
    {

        // mkdir the data and params directories if they don't exist; a directory that cannot be
        // created or probed (permissions, read-only filesystem, path too long) is reported as one clear line.
        if (!EnsureDirectoryExists(GetDataDir(false), "data directory") ||
            !EnsureDirectoryExists(ZC_GetParamsDir(), "zclassic params directory"))
            return false;

        if (!boost::filesystem::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
            return false;
        }

        
        try
        {
            ReadConfigFile(mapArgs, mapMultiArgs);
        } catch (const missing_zcash_conf& e) {
            boost::filesystem::path config_file_path = GetConfigFile();

            if (mapArgs.count("-conf")) {
                // An explicitly named configuration file is never created behind the user's back.
                fprintf(stderr, "Error: Specified configuration file \"%s\" does not exist or cannot be read.\n",
                        config_file_path.string().c_str());
                return false;
            }

            std::ofstream basic_conf_file (config_file_path.string());
            basic_conf_file << "txindex=1" << std::endl;
            basic_conf_file << "rpcuser=zcluser" << std::endl;
            basic_conf_file << "rpcpassword=zclpass" << std::endl;
            basic_conf_file.close();

        } catch (const std::exception& e) {
            // A configuration file that exists but cannot be parsed must not be overwritten.
            fprintf(stderr, "Error reading configuration file \"%s\": %s\n",
                    GetConfigFile().string().c_str(), e.what());
            return false;
        }

        try
        {
            ReadConfigFile(mapArgs, mapMultiArgs);
        } catch (const missing_zcash_conf& e) {
            fprintf(stderr,
                (_("Before starting zclassicd, you need to create a configuration file:\n"
                   "%s\n"
                   "It can be completely empty! That indicates you are happy with the default\n"
                   "configuration of zclassicd. But requiring a configuration file to start ensures\n"
                   "that zclassicd won't accidentally compromise your privacy if there was a default\n"
                   "option you needed to change.\n"
                   "\n"
                   "You can look at the example configuration file for suggestions of default\n"
                   "options that you may want to change. It should be in one of these locations,\n"
                   "depending on how you installed ZClassic:\n") +
                 _("- Source code:  %s\n"
                   "- .deb package: %s\n")).c_str(),
                GetConfigFile().string().c_str(),
                "contrib/examples/zclassic.conf",
                "/usr/share/doc/zcash/examples/zclassic.conf");
            return false;
        } catch (const std::exception& e) {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            return false;
        }
        // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
        if (!SelectParamsFromCommandLine()) {
            fprintf(stderr, "Error: Invalid combination of -regtest and -testnet.\n");
            return false;
        }

        // The network-specific data directory is created on first use; report a failure (permissions,
        // read-only filesystem, path too long) as one clear line instead of an uncaught exception.
        try {
            GetDataDir(true);
        } catch (const boost::filesystem::filesystem_error& e) {
            fprintf(stderr, "Error: Cannot create the data directory \"%s\": %s\n",
                    e.path1().string().c_str(), e.code().message().c_str());
            return false;
        }

        // Command-line RPC
        bool fCommandLine = false;
        for (int i = 1; i < argc; i++)
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "zclassic:"))
                fCommandLine = true;

        if (fCommandLine)
        {
            fprintf(stderr, "Error: There is no RPC client functionality in zclassicd. Use the zclassic-cli utility instead.\n");
            exit(EXIT_FAILURE);
        }
#ifndef WIN32
        fDaemon = GetBoolArg("-daemon", false);
        if (fDaemon)
        {
            fprintf(stdout, "ZClassic server starting\n");

            // Daemonize
            pid_t pid = fork();
            if (pid < 0)
            {
                fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
                return false;
            }
            if (pid > 0) // Parent process, pid is child process id
            {
                return true;
            }
            // Child process falls through to rest of initialization

            pid_t sid = setsid();
            if (sid < 0)
                fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
        }
#endif
        SoftSetBoolArg("-server", true);

        fRet = AppInit2(threadGroup, scheduler);
    }
    catch (const boost::filesystem::filesystem_error& e) {
        // A path problem while starting up (permissions, read-only filesystem, path too long): one clear line.
        fprintf(stderr, "Error: %s: \"%s\"\n", e.code().message().c_str(), e.path1().string().c_str());
        LogPrintf("AppInit: %s\n", e.what());
        fRet = false;
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }

    if (!fRet)
    {
        // Failed or cancelled initialization may already have started script
        // checks and the scheduler. They must leave before Shutdown tears down
        // shared state and before the stack-owned scheduler is destroyed.
        StartShutdown();
        Interrupt(threadGroup);
        threadGroup.join_all();
    } else {
        WaitForShutdown(&threadGroup);
    }
    Shutdown();

    return fRet;
}

#ifdef WIN32
/**
 * The C runtime hands main() the command line converted to the ANSI code page.
 * Characters the code page cannot represent become '?', which then fails with
 * "Invalid argument" or points at a different directory. With the UTF-8 active
 * code page manifest (Windows 10 1903+) the conversion is lossless; on older
 * Windows, refuse a lossy command line with a clear message instead.
 */
static bool WinCommandLineIsLossy()
{
    if (GetACP() == CP_UTF8) return false;
    int nArgs = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (!wargv) return false;
    bool lossy = false;
    // Skip argv[0]: the executable path is not used to open anything (the embedded
    // Tor child is located with GetModuleFileNameW), so a binary kept under a
    // non-ANSI folder with an ASCII datadir must keep working.
    for (int i = 1; i < nArgs && !lossy; i++) {
        BOOL usedDefault = FALSE;
        if (WideCharToMultiByte(CP_ACP, 0x00000400 /* WC_NO_BEST_FIT_CHARS */, wargv[i], -1, NULL, 0, "?", &usedDefault) > 0 && usedDefault)
            lossy = true;
    }
    LocalFree(wargv);
    return lossy;
}
#endif

int main(int argc, char* argv[])
{
    // -embeddedtormode=child re-executes this binary as its Tor process. That
    // role must be taken before anything else runs; in every other case this
    // returns -1 at once (and always does in a build without embedded Tor).
    int nTorChild = EmbeddedTorDispatch(argc, argv);
    if (nTorChild >= 0)
        return nTorChild;

#ifdef WIN32
    if (WinCommandLineIsLossy()) {
        fprintf(stderr,
                "Error: the command line contains characters that the system ANSI code page (%u) cannot represent,\n"
                "for example a non-ASCII -datadir, -conf or -exportdir path. Use Windows 10 version 1903 or later\n"
                "(this program asks for the UTF-8 code page), or use a path made of ANSI-representable characters.\n",
                GetACP());
        return EXIT_FAILURE;
    }
#endif

    SetupEnvironment();

    // Connect bitcoind signal handlers
    noui_connect();

    return (AppInit(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE);
}
