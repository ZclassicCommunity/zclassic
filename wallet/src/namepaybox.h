// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The box under a "Pay to" field that holds a name. It appears only when the entry starts with '@'; for any
// other entry it is hidden and the field is exactly what it always was.
//
// What it does: looks the name up through the daemon (the lookup is injected, so this file knows nothing of the
// network), shows the resolved ADDRESS in full with the registration facts and, prominently, any warning, and asks
// the user to confirm that address. Only a confirmed, current answer turns the entry into an address; the send path
// then uses that address exactly as if it had been pasted. If the name cannot be resolved, or the node has no name
// index, nothing changes for the field.
#ifndef ZCL_NAMEPAYBOX_H
#define ZCL_NAMEPAYBOX_H

#include <QFrame>
#include <QString>

#include <functional>

#include "namesmodel.h"

class QCheckBox;
class QLabel;
class QTimer;

class NamePayBox : public QFrame {
    Q_OBJECT
public:
    // Looks `name` up and calls back exactly once: ok == false when the daemon could not answer (index off, not
    // synced, no connection), with the error reply (or null) in `reply`; ok == true with the "result" member.
    typedef std::function<void(bool ok, const nlohmann::json& reply)> Reply;
    typedef std::function<void(const QString& name, const Reply& done)> ResolveFn;

    enum class State {
        Hidden,       // the entry is not a name
        Rejected,     // starts with '@' but is not a well-formed name
        Waiting,      // a name; the lookup starts after a short pause in typing
        Resolving,    // the lookup is running
        Resolved,     // the daemon answered (check usable() before offering the address)
        Failed,       // the daemon answered "no": absent, no payable record
        Unavailable   // the daemon could not answer: no index, not synced, no connection
    };

    explicit NamePayBox(ResolveFn resolve, QWidget* parent = nullptr);

    // Call on every edit of the field.
    void setFieldText(const QString& text);

    State state() const { return state_; }
    const QString& name() const { return name_; }
    const names::Resolution& resolution() const { return res_; }
    bool usable() const { return state_ == State::Resolved && assessment_.usable; }
    bool confirmed() const;

    // The address to put in the transaction for this field text. For a confirmed, current resolution of the very name
    // typed: the resolved address. For everything else: `fieldText` unchanged, so a field that is not a name (or a
    // name that did not resolve) behaves exactly as before.
    QString effectiveAddress(const QString& fieldText) const;

    // True (with the reason) while the entry is a name whose answer the user has not yet confirmed.
    bool blocksSending(const QString& fieldText, QString* why) const;

    // Ask again just before sending. done(true): the answer is the same and still confirmed; done(false): it changed
    // or could not be checked, the box says so and the confirmation is cleared.
    void recheck(const std::function<void(bool)>& done);

    // Lookup now, without waiting for the typing pause (the timer calls this; tests call it directly).
    void resolveNow();

    // Replace the lookup (tests drive the real Send tab with a fake one).
    void setResolver(ResolveFn resolve) { resolve_ = std::move(resolve); }

    // Test seams.
    QLabel* addressLabel() const { return addressLabel_; }
    QLabel* warningLabel() const { return warningLabel_; }
    QLabel* statusLabel() const { return statusLabel_; }
    QLabel* infoLabel() const { return infoLabel_; }
    QCheckBox* confirmCheck() const { return confirm_; }

signals:
    void changed();   // state, answer or confirmation changed: refresh whatever depends on them

private:
    void setState(State s);
    void applyReply(int token, bool ok, const nlohmann::json& reply);
    void showResolution();
    void clearAnswer();
    void recheckReply(int token, const names::Resolution& before, bool ok, const nlohmann::json& reply,
                      const std::function<void(bool)>& done);

    ResolveFn resolve_;
    QTimer* timer_;
    State state_ = State::Hidden;
    QString name_;
    QString folded_;           // "looked up as @alice" note when upper case was folded
    names::Resolution res_;
    names::Assessment assessment_;
    int token_ = 0;
    QString changedNote_;      // shown after a recheck found a different answer

    QLabel* statusLabel_;
    QLabel* addressTitle_;
    QLabel* addressLabel_;
    QLabel* infoLabel_;
    QLabel* warningLabel_;
    QCheckBox* confirm_;
};

#endif // ZCL_NAMEPAYBOX_H
