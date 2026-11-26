// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "phrase.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QHash>
#include <QRegularExpression>

namespace Phrase {

const QStringList& wordList() {
    static const QStringList words = []() {
        QStringList out;
        QFile f(":/img/res/bip39-english.txt");
        if (f.open(QIODevice::ReadOnly | QIODevice::Text))
            for (const QString& w : QString::fromLatin1(f.readAll()).split('\n'))
                if (!w.trimmed().isEmpty()) out << w.trimmed();
        return out;
    }();
    return words;
}

namespace {
const QHash<QString, int>& wordIndex() {
    static const QHash<QString, int> index = []() {
        QHash<QString, int> out;
        const QStringList& words = wordList();
        for (int i = 0; i < words.size(); ++i) out.insert(words.at(i), i);
        return out;
    }();
    return index;
}

bool isPrefixOfAWord(const QString& w) {
    for (const QString& word : wordList())
        if (word.startsWith(w)) return true;
    return false;
}

// The one list word w most likely meant: every BIP39 word is unique by its first
// four letters, so a word that starts like exactly one list word means that one.
QString suggestFor(const QString& w) {
    const QString stem = w.left(4);
    QString found;
    for (const QString& word : wordList()) {
        if (!word.startsWith(stem)) continue;
        if (!found.isEmpty()) return QString();
        found = word;
    }
    return found;
}

// The 24 words' 264 bits: the first 256 are the seed, the last 8 its checksum.
bool checksumMatches(const QStringList& words) {
    QByteArray bits(33, '\0');
    int bit = 0;
    for (const QString& w : words) {
        const int idx = wordIndex().value(w);
        for (int b = 10; b >= 0; --b, ++bit)
            if (idx & (1 << b)) bits[bit / 8] = char(bits[bit / 8] | (0x80 >> (bit % 8)));
    }
    const QByteArray digest = QCryptographicHash::hash(bits.left(32), QCryptographicHash::Sha256);
    return digest.at(0) == bits.at(32);
}
}   // namespace

QStringList split(const QString& text) {
    QStringList out;   // (Qt::SkipEmptyParts needs Qt 5.14; the CI root has 5.12)
    for (const QString& w : text.toLower().split(QRegularExpression("\\s+")))
        if (!w.isEmpty()) out << w;
    return out;
}

QStringList fromEntropy(const QByteArray& entropy) {
    if (entropy.size() != 32 || wordList().size() != 2048) return {};
    QByteArray bits = entropy;
    bits.append(QCryptographicHash::hash(entropy, QCryptographicHash::Sha256).at(0));
    QStringList out;
    for (int w = 0; w < kWords; ++w) {
        int idx = 0;
        for (int b = 0; b < 11; ++b) {
            const int bit = w * 11 + b;
            idx = (idx << 1) | ((uchar(bits.at(bit / 8)) >> (7 - bit % 8)) & 1);
        }
        out << wordList().at(idx);
    }
    return out;
}

Check check(const QString& text) {
    Check c;
    const QStringList words = split(text);
    c.count = words.size();
    if (c.count == 0) return c;
    const bool typingLast = !text.isEmpty() && !text.at(text.size() - 1).isSpace();
    for (int i = 0; i < words.size(); ++i) {
        if (wordIndex().contains(words.at(i))) continue;
        const bool last = i == words.size() - 1;
        if (last && typingLast && c.count < kWords && isPrefixOfAWord(words.at(i))) continue;
        c.state = Check::UnknownWord;
        c.word = i + 1;
        c.suggestion = suggestFor(words.at(i));
        return c;
    }
    if (c.count < kWords) { c.state = Check::Incomplete; return c; }
    if (c.count > kWords) { c.state = Check::TooMany; return c; }
    c.state = checksumMatches(words) ? Check::Valid : Check::BadChecksum;
    return c;
}

QString hint(const Check& c) {
    auto tr = [](const char* s) { return QCoreApplication::translate("Phrase", s); };
    switch (c.state) {
    case Check::Empty:       return tr("Type or paste your 24 words.");
    case Check::Incomplete:  return tr("%1 of 24 words").arg(c.count);
    case Check::TooMany:     return tr("Too many words: a phrase has 24.");
    case Check::UnknownWord:
        if (!c.suggestion.isEmpty())
            return tr("Word %1 isn't in the list. Did you mean “%2”?").arg(c.word).arg(c.suggestion);
        return tr("Word %1 isn't in the list").arg(c.word);
    case Check::BadChecksum: return tr("These words don't check out — look for a typo");
    case Check::Valid:       return tr("All 24 words check out.");
    }
    return QString();
}

}   // namespace Phrase
