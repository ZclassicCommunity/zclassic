// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "namepaybox.h"

#include <QCheckBox>
#include <QFontDatabase>
#include <QLabel>
#include <QTimer>
#include <QVBoxLayout>

namespace {
const int kTypingPauseMs = 400;
}

NamePayBox::NamePayBox(ResolveFn resolve, QWidget* parent)
    : QFrame(parent), resolve_(std::move(resolve)), timer_(new QTimer(this))
{
    setObjectName(QStringLiteral("NamePayBox"));
    setFrameShape(QFrame::StyledPanel);
    timer_->setSingleShot(true);
    timer_->setInterval(kTypingPauseMs);
    connect(timer_, &QTimer::timeout, this, &NamePayBox::resolveNow);

    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(8, 6, 8, 6);
    lay->setSpacing(4);

    statusLabel_ = new QLabel(this);
    statusLabel_->setObjectName(QStringLiteral("NameStatus"));
    statusLabel_->setWordWrap(true);
    lay->addWidget(statusLabel_);

    addressTitle_ = new QLabel(tr("The address to pay (nothing but this address goes into the transaction):"), this);
    addressTitle_->setObjectName(QStringLiteral("NameAddressTitle"));
    addressTitle_->setWordWrap(true);
    lay->addWidget(addressTitle_);

    addressLabel_ = new QLabel(this);
    addressLabel_->setObjectName(QStringLiteral("NameAddress"));
    addressLabel_->setWordWrap(true);
    addressLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono.setBold(true);
    addressLabel_->setFont(mono);
    lay->addWidget(addressLabel_);

    infoLabel_ = new QLabel(this);
    infoLabel_->setObjectName(QStringLiteral("NameInfo"));
    infoLabel_->setWordWrap(true);
    infoLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lay->addWidget(infoLabel_);

    warningLabel_ = new QLabel(this);
    warningLabel_->setObjectName(QStringLiteral("NameWarning"));
    warningLabel_->setWordWrap(true);
    warningLabel_->setTextFormat(Qt::PlainText);
    warningLabel_->setStyleSheet(QStringLiteral(
        "QLabel#NameWarning { color: #7a0000; background: #ffe3e0; border: 2px solid #c0392b; "
        "padding: 6px; font-weight: bold; }"));
    lay->addWidget(warningLabel_);

    confirm_ = new QCheckBox(this);
    confirm_->setObjectName(QStringLiteral("NameConfirm"));
    lay->addWidget(confirm_);
    connect(confirm_, &QCheckBox::toggled, this, [this](bool) { emit changed(); });

    clearAnswer();
    setVisible(false);
}

bool NamePayBox::confirmed() const
{
    return usable() && confirm_->isChecked();
}

void NamePayBox::clearAnswer()
{
    res_ = names::Resolution();
    assessment_ = names::Assessment();
    addressTitle_->setVisible(false);
    addressLabel_->clear();
    addressLabel_->setVisible(false);
    infoLabel_->clear();
    infoLabel_->setVisible(false);
    warningLabel_->clear();
    warningLabel_->setVisible(false);
    confirm_->blockSignals(true);
    confirm_->setChecked(false);
    confirm_->blockSignals(false);
    confirm_->setVisible(false);
}

void NamePayBox::setState(State s)
{
    state_ = s;
    setVisible(s != State::Hidden);
    emit changed();
}

void NamePayBox::setFieldText(const QString& text)
{
    const names::Parsed p = names::parsePayTo(text);
    if (p.kind == names::InputKind::Name && p.name == name_ &&
        (state_ == State::Resolved || state_ == State::Resolving || state_ == State::Waiting)) {
        return; // the same name again (a trailing space, a case change): keep the lookup, the answer and the confirmation
    }
    ++token_; // any lookup in flight is for something else now
    timer_->stop();
    changedNote_.clear();
    if (p.kind == names::InputKind::NotAName) {
        name_.clear();
        clearAnswer();
        statusLabel_->clear();
        setState(State::Hidden);
        return;
    }
    if (p.kind == names::InputKind::Rejected) {
        name_.clear();
        clearAnswer();
        statusLabel_->setText(p.problem);
        setState(State::Rejected);
        return;
    }
    name_ = p.name;
    folded_ = p.folded ? tr("(looked up as @%1: names have no upper case letters)").arg(p.name) : QString();
    clearAnswer();
    statusLabel_->setText(tr("Looking up @%1 ...").arg(name_));
    setState(State::Waiting);
    timer_->start();
}

void NamePayBox::resolveNow()
{
    if (name_.isEmpty() || !resolve_)
        return;
    timer_->stop();
    const int token = ++token_;
    statusLabel_->setText(tr("Looking up @%1 ...").arg(name_));
    setState(State::Resolving);
    resolve_(name_, [this, token](bool ok, const nlohmann::json& reply) { applyReply(token, ok, reply); });
}

void NamePayBox::applyReply(int token, bool ok, const nlohmann::json& reply)
{
    if (token != token_)
        return; // the entry changed while the daemon was answering
    clearAnswer();
    if (!ok) {
        QString why;
        if (reply.is_object()) {
            auto er = reply.find("error");
            if (er != reply.end() && er->is_object()) {
                auto m = er->find("message");
                if (m != er->end() && m->is_string())
                    why = QString::fromStdString(m->get<std::string>());
            }
        }
        statusLabel_->setText(tr("Names cannot be looked up here%1. Paste an address to pay.")
                                  .arg(why.isEmpty() ? QString() : QStringLiteral(" (") + why.left(160) + QStringLiteral(")")));
        setState(State::Unavailable);
        return;
    }
    if (!names::parseResolution(reply, &res_)) {
        res_ = names::Resolution();
        statusLabel_->setText(tr("The node's answer about @%1 could not be understood.").arg(name_));
        setState(State::Unavailable);
        return;
    }
    assessment_ = names::assess(res_);
    if (!res_.resolved) {
        statusLabel_->setText(assessment_.headline);
        setState(State::Failed);
        return;
    }
    showResolution();
    setState(State::Resolved);
}

void NamePayBox::showResolution()
{
    QString head = assessment_.headline;
    if (!folded_.isEmpty())
        head += QLatin1Char(' ') + folded_;
    if (!changedNote_.isEmpty())
        head = changedNote_ + QLatin1Char('\n') + head;
    statusLabel_->setText(head);
    if (assessment_.usable) {
        addressTitle_->setVisible(true);
        addressLabel_->setText(res_.address);
        addressLabel_->setVisible(true);
        confirm_->setText(assessment_.strongWarning
                              ? tr("I have confirmed this address with the recipient and want to pay it")
                              : tr("This is the address I mean to pay"));
        confirm_->setVisible(true);
    }
    infoLabel_->setText(assessment_.info);
    infoLabel_->setVisible(!assessment_.info.isEmpty());
    warningLabel_->setText(assessment_.warnings.join(QStringLiteral("\n\n")));
    warningLabel_->setVisible(!assessment_.warnings.isEmpty());
}

QString NamePayBox::effectiveAddress(const QString& fieldText) const
{
    const names::Parsed p = names::parsePayTo(fieldText);
    if (p.kind != names::InputKind::Name || p.name != name_ || !confirmed())
        return fieldText;
    return res_.address;
}

bool NamePayBox::blocksSending(const QString& fieldText, QString* why) const
{
    const names::Parsed p = names::parsePayTo(fieldText);
    if (p.kind != names::InputKind::Name)
        return false;
    if (state_ == State::Waiting || state_ == State::Resolving) {
        if (why)
            *why = tr("@%1 is still being looked up. Wait for the address to appear, check it and confirm it.").arg(p.name);
        return true;
    }
    if (state_ == State::Resolved && usable() && !confirmed()) {
        if (why)
            *why = tr("Check the address shown for @%1 and tick the box to confirm it before sending.").arg(p.name);
        return true;
    }
    return false;
}

void NamePayBox::recheck(const std::function<void(bool)>& done)
{
    if (state_ != State::Resolved || !usable() || !resolve_) {
        done(true); // nothing to re-check: the entry is not a confirmed name answer
        return;
    }
    const int token = ++token_;
    const names::Resolution before = res_;
    const QString nm = name_;
    resolve_(nm, [this, token, before, done](bool ok, const nlohmann::json& reply) {
        if (token != token_) {
            done(false);
            return;
        }
        names::Resolution now;
        if (!ok || !names::parseResolution(reply, &now)) {
            confirm_->setChecked(false);
            changedNote_ = tr("@%1 could not be checked again just now, so nothing was sent. Try again.").arg(name_);
            showResolution();
            emit changed();
            done(false);
            return;
        }
        if (names::sameAnswer(before, now)) {
            res_ = now;                       // fresher recency numbers; the confirmation stands
            assessment_ = names::assess(res_);
            showResolution();
            emit changed();
            done(true);
            return;
        }
        res_ = now;
        assessment_ = names::assess(res_);
        changedNote_ = tr("The answer for @%1 CHANGED while you were checking it: nothing was sent. Review the new address.").arg(name_);
        confirm_->blockSignals(true);
        confirm_->setChecked(false);
        confirm_->blockSignals(false);
        if (res_.resolved)
            showResolution();
        else
            statusLabel_->setText(changedNote_ + QLatin1Char('\n') + assessment_.headline);
        emit changed();
        done(false);
    });
}
