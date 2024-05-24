# python3_final
final project for python3
# PicVibe

PicVibe is a web application that allows users to upload, view, like, and dislike images. Users can sign up, log in, and interact with a gallery of images uploaded by other users. The application features image upload via file selection or pasting, and it displays images in a gallery format where users can vote on each image.

## Features

- **User Authentication**
  - Sign up and log in functionality
  - Email verification for new users
  - Password hashing for secure storage of user credentials

- **Image Upload**
  - Users can upload images by selecting a file or pasting an image
  - Images are displayed in a gallery format
  - Users can like or dislike images

- **Voting System**
  - Users can vote on images, and the votes are displayed as like and dislike percentages

- **Navigation**
  - Users can navigate between different images in the gallery
  - Links to the home page and user profile

## Technologies Used

- **Flask**: A lightweight WSGI web application framework for Python
- **SQLite**: A lightweight, disk-based database used to store user and image data
- **Flask-WTF**: Integrates WTForms with Flask for form validation and rendering
- **Flask-Mail**: Provides email sending capabilities
- **Jinja2**: Templating engine for rendering HTML templates
- **Pillow (PIL)**: Python Imaging Library used for image processing
- **Werkzeug**: Provides utilities for password hashing and secure filename handling
- **JavaScript**: Enhances client-side interactivity and handles image uploads

## Security Measures

1. **Password Hashing**
   - User passwords are hashed using Werkzeug's `generate_password_hash` before storing them in the database
   - Passwords are checked using `check_password_hash` during login

2. **CSRF Protection**
   - Forms are protected against Cross-Site Request Forgery (CSRF) attacks using Flask-WTF's CSRF tokens

3. **Email Verification**
   - New users must verify their email address by entering a token sent to their email
   - Ensures the authenticity of user email addresses

4. **Session Management**
   - User sessions are managed securely to ensure only authenticated users can access certain features

5. **Input Validation**
   - User inputs are validated using Flask-WTF to prevent common web vulnerabilities such as SQL injection and cross-site scripting (XSS)

## Installation and Setup

### Prerequisites

- Python 3.x
- pip (Python package installer)
- Virtual environment (optional but recommended)

### Clone the Repository

```sh
git clone https://github.com/NikolozTchitanava/picvibe.git
cd picvibe
