// fixture: reads of flags
void ReadFlags()
{
    int foo = GetArg("-foo", 1);
    bool bar = GetBoolArg("-bar", false);
    bool nodebug = GetBoolArg("-nodebug", false);
    if (mapArgs.count("-hidden")) return;
    // GetArg("-" + name) is computed and ignored
    GetArg("-" + name, 0);
    SetArg("-notread");
}
