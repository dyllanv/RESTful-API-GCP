# RESTful-API-GCP

Portfolio Assignment for Cloud Application Development

"""
You will need to implement a REST API that uses proper resource based URLs, pagination and status codes. In addition you will need to implement some sort of system for creating users and for authorization. You will deploy your application on Google Cloud Platform.

The default is that you must use:
- Datastore to store your data, and
- Either Node.js or Python 3, and
- Google App Engine to deploy your project

Your application needs to have:

- An entity to model the user.
- At least two other non-user entities.
- The two non-user entities need to be related to each other.
- The user needs to be related to at least one of the non-user entities.
- Resources corresponding to the non-user entity related to the user must be protected.
"""

This RESTful API is hosted via Google Cloud Platform at: https://cs493-portfolio-314720.wl.r.appspot.com/


### Project Flow/Use

Following this link will bring the user to a page with a link to login via Google using OAuth 2.0 (self implemented, no 3rd-party libraries).

From there, the user will be asked to share their basic profile information. 

The user will then be redirected to a page that displays their name, their user id (taken from the 'sub' property of the JSON Web Token provided by Google), and the JSON Web Token itself. Make sure to copy this JWT for further use.

When the user logs in and receives a JWT, a user account is automatically created and stored in the site's database (Google Cloud's Datastore).

The JSON Web Token must then be used in the Authorization header of each request to access the rest of the functionality of the API.

Only users with valid JWTs can create, read, edit, and delete the protected resources (boats and loads).

Users with valid JWTs can assign and remove existing loads to/from existing boats.

Users can read and delete their accounts. Deleting an account would in turn delete all boats and loads owned by the user (this process utilizes multithreading for the multiple requests to datastore). 

API contains one unprotected route for getting all users with an account. No JWT needed (for grading purposes). All other routes are protected and require valid JWTs.


### Project Specs

Only supports GET, POST, PUT, PATCH, and DELETE requests.
All requests requiring a body must be in JSON, and all accept mimetypes must also be JSON. 
Results for getting all boats or loads of a given user are returned 5 at a time using pagination.
Thorough input validation and custom error handling: (see API Doc for details).

Project built with Python3, the Flask microframework, and the Google Cloud SDK.\
Flask Blueprint used for modularizing app.\
Postman used for testing (see provided test environment and collection).\
See API Doc for specifications on routes, requests, and responses.

