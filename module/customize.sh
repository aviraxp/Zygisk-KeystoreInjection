# Error on < Android 14.
if [ "$API" -lt 30]; then
    abort "- !!! You can't use this module on Android < 11"
fi
