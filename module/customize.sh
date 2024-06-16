# Error on < Android 14.
if [ "$API" -lt 34 ]; then
    abort "- !!! You can't use this module on Android < 14"
fi
