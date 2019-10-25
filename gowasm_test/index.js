require('./wasm_exec.js');
require('isomorphic-fetch');

const { join } = require('path');
const { readFileSync } = require('fs');
const go = new global.Go();

global.requestAnimationFrame = global.setImmediate;
global.diode = {};

let wasmBytes = readFileSync(join(__dirname, 'main.wasm'));

function proxyCall(obj, functionName, ...args) {
  return new Promise(function (resolve, reject) {
    if (typeof obj[functionName] === 'undefined') {
      reject(new Error('Cannot find the function'));
    }
    if (typeof obj[functionName] !== 'function') {
      resolve(obj[functionName]);
    }
    obj[functionName].call(undefined, ...args, function (err, res) {
      if (err) {
        reject(err);
      }
      resolve(res);
    });
  });
}

async function run() {
  try {
  let wasmInstance = await WebAssembly.instantiate(wasmBytes, go.importObject);
  go.run(wasmInstance.instance);
  diode.add(1, 2, 0.1, 'g', function (err, result) {
    console.log(result);
  });
  console.log(await proxyCall(diode, 'hhh'));
  console.log(await proxyCall(diode, 'add', 1, 3, 5.1));
  console.log(await proxyCall(diode, 'add', 1, 3, 9.16));
  console.log(await proxyCall(diode, 'callRpc', 'http://localhost:8081'));
    // console.log(await proxyCall(diode, 'listen'));
    // console.log('Start')
    // for (;;) {}
  } catch (err) {
    console.log(err.message)
  }
};

run()