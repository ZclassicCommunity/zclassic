// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef PHRASE_H
#define PHRASE_H

#include <QByteArray>
#include <QString>
#include <QStringList>

// The wallet's 24-word recovery phrase as the GUI sees it: the BIP39 English
// wordlist and checksum (256 bits of seed + an 8-bit SHA-256 checksum = 24 words
// of 11 bits). The node owns the seed; here the words are only checked so the
// Restore field can say what is wrong while the user types. Pure functions.
namespace Phrase {

const int kWords = 24;

// The 2048 BIP39 English words, in order (res/bip39-english.txt).
const QStringList& wordList();

// The words of a typed or pasted phrase: lower case, any spacing.
QStringList split(const QString& text);

// 32 seed bytes -> 24 words; empty for any other length. Used by tests.
QStringList fromEntropy(const QByteArray& entropy);

struct Check {
    enum State { Empty, Incomplete, TooMany, UnknownWord, BadChecksum, Valid };
    State   state = Empty;
    int     count = 0;        // words typed
    int     word  = 0;        // 1-based position of an unknown word
    QString suggestion;       // the list word it most likely meant, if one
};

// Where a typed phrase stands. A last word that is still being typed (a prefix
// of a list word) is not reported as unknown.
Check check(const QString& text);

// One short line for the Restore field ("12 of 24 words", ...).
QString hint(const Check& c);

}   // namespace Phrase

#endif // PHRASE_H
