// fixture: command-line help
std::string HelpMessage(HelpMessageMode mode)
{
    string strUsage = HelpMessageGroup(_("Options:"));
    strUsage += HelpMessageOpt("-?", _("This help message"));
    strUsage += HelpMessageOpt("-foo=<n>", strprintf(_("Foo (default: %u)"), 1));
    strUsage += HelpMessageOpt("-debug=<category>", _("Output debugging information") + ". " +
        _("Not enabled by default"));
    strUsage += HelpMessageGroup(_("Wallet options:"));
    strUsage += HelpMessageOpt("-bar", _("Bar, a switch"));
    return strUsage;
}
