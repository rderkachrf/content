var hash = args.hash;
var flat = {};
var res = [];
var currentValue;
flattenFields(invContext,undefined,flat);
keysArr = Object.keys(flat);
for (var i = 0; i < keysArr.length; i++) {
    currentValue=flat[keysArr[i]];
    if (hashRegex.test(currentValue) && res.indexOf(currentValue) === -1) {
        switch(hash) {
        case 'MD5':
            if (currentValue.length === 32) {
                res.push(currentValue);
            }
            break;
        case 'SHA1':
            if (flat[keysArr[i]].length === 40) {
                res.push(currentValue);
            }
            break;
        case 'SHA256':
            if (flat[keysArr[i]].length === 64) {
                res.push(currentValue);
            }
            break;
        case 'all':
            if ([32,40,64].indexOf(flat[keysArr[i]].length) > -1) {
                res.push(currentValue);
            }
            break;
        default:
        }
    }
}
var md = '### Hashes (' + hash + ') in context\n';
for (var i = 0; i<res.length; i++) {
    md += '- ' + res[i] + '\n';
}
return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md
        };

