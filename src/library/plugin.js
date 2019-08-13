import GSCWeb3 from 'index';
import tools from 'tools';
import semver from 'semver';

export default class Plugin {

    constructor(gscWeb3 = false) {
        if (!gscWeb3 || !gscWeb3 instanceof GSCWeb3)
            throw new Error('Expected instance of GSCWeb3');
        this.gscWeb3 = gscWeb3;
        this.pluginNoOverride = ['register'];
    }

    register(Plugin, options) {
        let pluginInterface = {
            requires: '0.0.0',
            components: {}
        }
        let result = {
            plugged: [],
            skipped: []
        }
        const plugin = new Plugin(this.gscWeb3)
        if (tools.isFunction(plugin.pluginInterface)) {
            pluginInterface = plugin.pluginInterface(options)
        }
        if (semver.satisfies(GSCWeb3.version, pluginInterface.requires)) {
            for (let component in pluginInterface.components) {
                if (!this.gscWeb3.hasOwnProperty(component)) {
                    // TODO implement new sub-classes
                    continue
                }
                let methods = pluginInterface.components[component]
                let pluginNoOverride = this.gscWeb3[component].pluginNoOverride || []
                for (let method in methods) {
                    if (method === 'constructor' || (this.gscWeb3[component][method] &&
                        (pluginNoOverride.includes(method) // blacklisted methods
                            || /^_/.test(method)) // private methods
                    )) {
                        result.skipped.push(method)
                        continue
                    }
                    this.gscWeb3[component][method] = methods[method].bind(this.gscWeb3[component])
                    result.plugged.push(method)
                }
            }
        } else {
            throw new Error('The plugin is not compatible with this version of GSCWeb3')
        }
        return result
    }
}

