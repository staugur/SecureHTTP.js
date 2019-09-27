import babel from "rollup-plugin-babel";
import { uglify } from "rollup-plugin-uglify";

const packages = require('./package.json');
const ENV = process.env.NODE_ENV || 'development';

const fileNames = {
    development: `${packages.name}.js`,
    production: `${packages.name}.min.js`
};

const fileName = fileNames[ENV];

export default {
    input: "SecureHTTP.js",
    output: {
        file: `./dist/${fileName}`,
        format: "umd",
        name: 'securehttp'
    },
    plugins: [
        (ENV === "production" && uglify()),
        babel({
            exclude: 'node_modules/**',
        })
    ],
};