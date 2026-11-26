// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BACKUPPAGE_H
#define BACKUPPAGE_H

#include <QStringList>
#include <QWidget>
#include <functional>

class QAction;
class QGridLayout;
class QGroupBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QTreeWidget;
class QVBoxLayout;

// The Backup page: the 24-word recovery phrase (show, write down, check), restore
// from a phrase, money on addresses the phrase does not cover, and the wallet.dat /
// private key files. It talks to nobody itself: MainWindow (backupwiring.cpp) feeds
// it the node's answers and runs what its callbacks ask for. The words are kept in
// widgets only while shown, and are never copied to the clipboard.
class BackupPage : public QWidget {
public:
    explicit BackupPage(QWidget* parent = nullptr);

    // Asked of MainWindow.
    std::function<void()>                 onShowPhrase;   // fetch the words -> showWords()
    std::function<void(const QString&)>   onRestore;      // the user confirmed a valid phrase
    std::function<void(const QString&)>   onMove;         // pre-fill Send from this address
    std::function<double(const QString&)> balanceOf;      // negative: not known yet

    // From the node. setSupported(false): a node without the phrase RPCs; only the
    // file card shows, as before.
    void setSupported(bool supported);
    bool isSupported() const { return _supported; }
    void setPhraseInfo(bool available, const QString& fingerprint, const QStringList& notCovered);
    void showWords(const QStringList& words, const QString& fingerprint);
    void hideWords();
    void setRestoring(bool busy);
    void clearRestoreField();
    bool isRestoring() const { return _restoring; }
    // The current phrase was written down and checked.
    bool isPhraseWritten() const { return isWrittenDown(_fingerprint); }
    // No older address outside the phrase holds money. A balance that is not known
    // yet counts as money: the Home reminder must not stop on a guess.
    bool coversEverything() const;
    void addFileActions(QAction* backup, QAction* exportKeys, QAction* importKeys);
    void refreshNotCovered();

    // The phrase with this fingerprint was written down and checked (or typed in to
    // restore): QSettings "backup/phrase/<fingerprint>".
    static bool isWrittenDown(const QString& fingerprint);
    static void setWrittenDown(const QString& fingerprint);

private:
    // Stops the Home backup reminder once the phrase is written down AND covers all
    // the money here; with money on older addresses the reminder stays.
    void noteBackedUp();
    bool _restoring = false;

private:
    QGroupBox* buildPhraseCard();
    QGroupBox* buildRestoreCard();
    QGroupBox* buildNotCoveredCard();
    QGroupBox* buildFilesCard();
    QWidget*   buildCheckStep(QWidget* parent);
    QLabel*    caption(const QString& text, QWidget* parent);
    void       updateStatus();
    void       startCheck();
    void       runCheck();
    void       restoreTextChanged();
    void       confirmRestore();

    bool         _supported = false;
    bool         _available = false;
    QString      _fingerprint;
    QString      _shownFingerprint;
    QStringList  _notCovered;
    QStringList  _words;         // only while shown
    QList<int>   _asked;         // 0-based positions the check step asks for

    QGroupBox*   _phraseCard     = nullptr;
    QGroupBox*   _restoreCard    = nullptr;
    QGroupBox*   _notCoveredCard = nullptr;
    QGroupBox*   _filesCard      = nullptr;
    QLabel*      _status         = nullptr;
    QWidget*     _grid           = nullptr;
    QList<QLabel*> _cells;
    QPushButton* _showBtn        = nullptr;
    QPushButton* _wroteBtn       = nullptr;
    QWidget*     _checkStep      = nullptr;
    QList<QLabel*>    _checkLabels;
    QList<QLineEdit*> _checkInputs;
    QLabel*      _checkResult    = nullptr;
    QPlainTextEdit* _restoreField = nullptr;
    QLabel*      _restoreHint    = nullptr;
    QPushButton* _restoreBtn     = nullptr;
    QProgressBar* _restoreBusy   = nullptr;
    QTreeWidget* _notCoveredList = nullptr;
    QVBoxLayout* _filesRow       = nullptr;
};

#endif // BACKUPPAGE_H
