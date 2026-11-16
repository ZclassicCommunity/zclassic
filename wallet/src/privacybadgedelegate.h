// ============================================================================
// PrivacyBadgeDelegate — the visual centerpiece of the "Quiet+" redesign
// (Phase 2). A QStyledItemDelegate that paints a persistent privacy badge next
// to every address and renders amounts in a monospace, tabular, sign-coloured
// style so columns line up and privacy is legible at a glance.
//
// PURE RESTYLE: this is installed from code via QTableView::setItemDelegate-
// ForColumn() — no .ui widget add/remove/rename and no model API change — so
// the L0/L1/L2 test harness stays green by construction.
//
//   * Address column  -> a small rounded pill:
//        green  "Private"          (shield-lock)  z / Sapling addresses
//        green  "Private (legacy)" (shield-lock)  Sprout z-addresses
//        amber  "PUBLIC"           (open eye)     t (transparent) addresses
//        red    "De-shield"        (eye-off)      a private->transparent leak
//   * Amount column   -> right-aligned monospace w/ tabular figures; the sign
//        is tinted subtly (received vs sent) without shouting.
//
// Performance: the tinted badge icons are rendered ONCE and cached (keyed by
// kind+size); paint() allocates no pixmaps. Null/empty cells fall through to
// the base QStyledItemDelegate so nothing is ever drawn for blank rows.
// ============================================================================
#ifndef PRIVACYBADGEDELEGATE_H
#define PRIVACYBADGEDELEGATE_H

#include "precompiled.h"
#include <QStyledItemDelegate>
#include <QHash>
#include <QPixmap>

class PrivacyBadgeDelegate : public QStyledItemDelegate {
    Q_OBJECT
public:
    // mode selects which column role this delegate instance serves. One table
    // installs an Address instance on its address column and an Amount instance
    // on its amount column (setItemDelegateForColumn).
    enum class Mode { Address, Amount };

    explicit PrivacyBadgeDelegate(Mode mode, QObject* parent = nullptr);

    void paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const override;
    QSize sizeHint(const QStyleOptionViewItem& option,
                   const QModelIndex& index) const override;

    // The privacy classification of an address, and the badge it maps to. Public so
    // the L0/L1 tests (PRIV-13/14) can name the categories; the classify*/labelFor/
    // colorFor logic stays the single source of truth (no duplicated truth table).
    enum class Kind { None, Private, PrivateLegacy, Public, Deshield };

#ifdef ZCL_WIDGET_TEST
    // TEST-ONLY SEAMS (PRIV-13/14): forward to the private static logic so the unit
    // tests exercise the REAL classify()/classifyForIndex()/labelFor()/colorFor()
    // without duplicating it. Compiled in ONLY under ZCL_WIDGET_TEST (the L1 widget
    // target); never present in the shipped app. colorFor is returned as an
    // "#rrggbb" string so the test can compare against the dark.qss hex tokens.
    static Kind    testClassify(const QString& displayText)            { return classify(displayText); }
    static Kind    testClassifyForIndex(const QModelIndex& i,
                                        const QString& displayText)     { return classifyForIndex(i, displayText); }
    static QString testLabelFor(Kind k)                                 { return labelFor(k); }
    static QString testColorHexFor(Kind k)                              { return colorFor(k).name(); }
#endif

private:

    Mode _mode;

    // Classify a display string (which may carry an addressbook "label (addr)"
    // suffix) into a badge kind. Prefers Settings::isZAddress/isTAddress/
    // isSaplingAddress/isSproutAddress; falls back to a cheap prefix check so
    // display never silently fails on an address Settings can't checksum-verify.
    static Kind classify(const QString& displayText);

    // SP-1: the original classify() body, factored out so classify() above can be
    // a thin memoized wrapper. Kept STATIC so the existing test seams
    // (testClassify/testClassifyForIndex) and the static classifyForIndex() keep
    // calling classify() exactly as before -- no signature or static-ness change
    // anywhere the tests or paint() touch. classify() runs only on the GUI thread
    // (the delegate paint path), so its function-local static memo needs no lock.
    static Kind classifyUncached(const QString& displayText);

    // Context-aware upgrade: in the transactions table a *send* to a public
    // (transparent) recipient is a privacy-leaking DE-SHIELD; promote that one
    // case to the red variant. Reads the sibling Type cell (column 0) of the
    // SAME row via the model, so it only fires where a Type column exists (the
    // transactions table) and never on the balances table. Null/role-safe.
    static Kind classifyForIndex(const QModelIndex& index, const QString& displayText);

    // Pull a bare address out of an addressbook-decorated display string of the
    // form "label (zs1...)"; returns the input trimmed if there's no suffix.
    static QString extractAddress(const QString& displayText);

    // Badge label + token color for a kind.
    static QString labelFor(Kind k);
    static QColor  colorFor(Kind k);

    // Return a tinted, cached badge icon for kind k at the given pixel height.
    // Renders the bundled SVG silhouette as an alpha mask and fills it with the
    // badge color; falls back to an empty (text-only) pixmap if SVG is absent.
    const QPixmap& icon(Kind k, int px) const;

    // The cache is mutable so the const paint()/sizeHint() can populate it.
    mutable QHash<QString, QPixmap> _iconCache;

    // The shared monospace/tabular font used for the amount column.
    static QFont monoFont();
};

#endif // PRIVACYBADGEDELEGATE_H
