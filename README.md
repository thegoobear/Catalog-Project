# Catalog Project

What it is:

 * A small example site for managing a catalog

What it does:

 * User login witih Oauth
 * Edit, Add, And Delete Items within catagories
 * Provide a JSON endpoint


## How to use it

### Intallation

Fork https://github.com/thegoobear/Catalog-Project

Start by running the database_setup.py file in the terminal:

```
python database_setup.py
```

Next, add a few dummy DB entries with testfill.py:

```
python testfill.py
```

Ensure you have all dependencies:

```
pip install -r requirements.txt
```

### Running the App

Start the app:

```
python catalog.py
```

#### The server will be available at localhost:5000

The site itself should be easily navigated. The json endpoint is at /catalog.json

## Stuff used to make this:

 * [Flask-Uploads](https://pythonhosted.org/Flask-Uploads/) for upload handling
 * [WTForms](https://wtforms.readthedocs.io/en/latest/) and [Flask-WTF](https://flask-wtf.readthedocs.io/en/stable/) for form and CSRF handling
 * [SQL Alchemy](https://www.sqlalchemy.org) for ORM
 * [SASS](http://sass-lang.com) for CSS management
