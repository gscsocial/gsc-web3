import {AbiCoder} from './ethersUtils';
import GSCWeb3 from 'index';
import {ADDRESS_PREFIX, ADDRESS_PREFIX_REGEX} from 'tools/address';

const abiCoder = new AbiCoder();

export function decodeParams(names, types, output, ignoreMethodHash) {

    if (!output || typeof output === 'boolean') {
        ignoreMethodHash = output;
        output = types;
        types = names;
        names = [];
    }

    if (ignoreMethodHash && output.replace(/^0x/, '').length % 64 === 8)
        output = '0x' + output.replace(/^0x/, '').substring(8);

    if (output.replace(/^0x/, '').length % 64)
        throw new Error('Error: code id: 10015');

    return abiCoder.decode(types, output).reduce((obj, arg, index) => {
        if (types[index] == 'address')
            arg = ADDRESS_PREFIX + arg.substr(2).toLowerCase();

        if (names.length)
            obj[names[index]] = arg;
        else obj.push(arg);

        return obj;
    }, names.length ? {} : []);
}

export function encodeParams(types, values) {

    for (let i = 0; i < types.length; i++) {
        if (types[i] === 'address') {
            values[i] = GSCWeb3.address.toHex(values[i]).replace(ADDRESS_PREFIX_REGEX, '0x');
        }
    }

    return abiCoder.encode(types, values);
}
