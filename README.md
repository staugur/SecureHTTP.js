# SecureHTTP.js

Make HTTP transmissions more secure via RSA+AES, encrypted communication for nodejs or browser.

## 说明

这个库基于brix/crypto-js、ArnaudValensi/node-jsencrypt实现，使用nodejs编写（位于src），经过rollup打包后支持浏览器端调用（位于dist，全局变量是securehttp）。

## 开发

- 下载

    - `git clone https://github.com/staugur/SecureHTTP.js`

    - `yarn add securehttp` 或 `npm install securehttp`

- 依赖

    请最好使用yarn安装依赖： `yarn` 或 `npm install`

- 测试 

    `yarn run test` 或 `npm run test`

- 打包开发版本

    `yarn run build`

- 打包正式版本（压缩）

    `yarn run dist`

## CDN

已经把压缩的正式版本放到又拍云的CDN上，包括开发版、正式版。

- 开发版 `https://static.saintic.com/securehttp.js/{ version }/securehttp.js`

- 正式版 `https://static.saintic.com/securehttp.js/{ version }/securehttp.min.js`

## 更多文档

https://docs.saintic.com/securehttp.js
