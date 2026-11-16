#ifndef GUISTARTUP_H
#define GUISTARTUP_H

// ----------------------------------------------------------------------------
// GUI startup timing — the client-side mirror of the daemon's [startup] log.
//
// A single process-global monotonic clock plus a handful of milestone deltas,
// recorded as the app boots and flushed as ONE "[gui-startup]" summary line the
// first time the wallet is actually usable (first balance painted). Lets us put
// the perceived time-to-usable next to the daemon's own warmup numbers.
//
// Design constraints honoured:
//   * Header-only, C++14: the storage lives in function-local statics inside
//     inline functions, so there is exactly ONE instance per process across all
//     translation units (one-definition rule for inline functions) and NO new
//     .cpp / .pro wiring is needed.
//   * Zero owning-QObject / UAF surface: this is plain POD + a QElapsedTimer,
//     touched only on the GUI thread on the startup path. It registers no
//     timers, no signals, no lambdas — nothing to outlive a fast quit.
//   * Negligible, always-on cost: a mark is one QElapsedTimer::elapsed() (a
//     clock read) + a store. The one logged line is emitted once per process.
//   * Some milestones (main()/QApplication) happen BEFORE the MainWindow Logger
//     exists, so we RECORD numbers here as we pass each point and only LOG once
//     a logger is available. Each milestone is recorded at most once (the first
//     write wins) so a re-entered path can never rewrite an earlier number.
// ----------------------------------------------------------------------------

#include <QElapsedTimer>
#include <QString>

namespace GuiStartup {

// The process clock. Started once, at the very top of main(). elapsed() on an
// unstarted timer returns 0, so any milestone marked before start() reads 0 —
// harmless, and in practice start() is the very first thing main() does.
inline QElapsedTimer& clock() {
    static QElapsedTimer t;
    return t;
}

// Recorded milestone deltas (ms since clock() start). -1 == "not reached yet".
struct Marks {
    qint64 mainStart      = -1;   // process/main() entry (clock zero)
    qint64 qAppConstructed = -1;  // QApplication/SingleApplication built
    qint64 windowShown    = -1;   // first MainWindow show() requested
    qint64 daemonSpawned  = -1;   // owned zclassicd process spawned
    qint64 firstGetInfo   = -1;   // first successful getinfo (RPC attached)
    qint64 firstBalance   = -1;   // first balance painted (usable)
    bool   summaryLogged  = false;
};

inline Marks& marks() {
    static Marks m;
    return m;
}

// Start the clock and record the main()-entry milestone (delta 0). Idempotent.
inline void begin() {
    if (!clock().isValid())
        clock().start();
    if (marks().mainStart < 0)
        marks().mainStart = clock().elapsed();
}

// Record a milestone, first-write-wins. Safe to call before clock().start()
// (reads 0). dst is one of the Marks fields above.
inline void mark(qint64& dst) {
    if (dst < 0)
        dst = clock().isValid() ? clock().elapsed() : 0;
}

inline void markQAppConstructed() { mark(marks().qAppConstructed); }
inline void markWindowShown()     { mark(marks().windowShown); }
inline void markDaemonSpawned()   { mark(marks().daemonSpawned); }
inline void markFirstGetInfo()    { mark(marks().firstGetInfo); }
inline void markFirstBalance()    { mark(marks().firstBalance); }

// Build the one-line "[gui-startup]" summary. Fields not yet reached print "-".
inline QString summaryLine() {
    auto f = [](qint64 v) -> QString {
        return v < 0 ? QStringLiteral("-") : QString::number(v);
    };
    const Marks& m = marks();
    return QStringLiteral("[gui-startup] main=0 qapp=%1 window=%2 daemon=%3 "
                          "getinfo=%4 balance=%5 (ms; usable=%5)")
        .arg(f(m.qAppConstructed), f(m.windowShown), f(m.daemonSpawned),
             f(m.firstGetInfo),    f(m.firstBalance));
}

} // namespace GuiStartup

#endif // GUISTARTUP_H
