import babel from 'rollup-plugin-babel';
import resolve from 'rollup-plugin-node-resolve';
import commonjs from 'rollup-plugin-commonjs';
import builtins from 'rollup-plugin-node-builtins';
import { uglify } from 'rollup-plugin-uglify';

const packages = require('./package.json');
const ENV = process.env.NODE_ENV || 'development';

const fileNames = {
    development: `${packages.name}.js`,
    production: `${packages.name}.min.js`
};

const fileName = fileNames[ENV];

export default {
    input: "src/securehttp.js",
    output: {
        file: `./dist/${fileName}`,
        format: "umd",
        name: "securehttp",
        exports: "named",
        sourcemap: true,
        globals: {
            'crypto-js': 'CryptoJS',
            'jsencrypt': 'JSEncrypt'
        }
    },
    plugins: [
        builtins(),
        resolve(),
        commonjs(),
        babel({
            exclude: 'node_modules/**',
        }),
        (ENV === "production" && uglify())
    ]
};