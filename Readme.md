# User Authentication System

This project is a Node.js-based user authentication system built using Express, MongoDB, and JSON Web Tokens (JWT). It provides features for user registration, login, and password reset, with a focus on security and best practices.

## Features

* **User Registration:** Allows users to create new accounts with secure password hashing.
* **User Login:** Authenticates users and generates JWT tokens for secure access.
* **Password Reset:** Enables users to reset their passwords via email.
* **JWT Authentication:** Uses JWT for secure API authentication.
* **Input Validation:** Implements input validation using `express-validator` to prevent common vulnerabilities.
* **MongoDB Integration:** Stores user data in a MongoDB database.
* **Environment Variable Configuration:** Uses `.env` files for secure configuration management.

## Technologies

* **Node.js:** JavaScript runtime environment.
* **Express.js:** Web application framework.
* **MongoDB:** NoSQL database.
* **Mongoose:** MongoDB object modeling tool.
* **bcryptjs:** Password hashing library.
* **jsonwebtoken:** JWT library.
* **dotenv:** Environment variable management.
* **express-validator:** Input validation library.
* **cors:** Cross-Origin Resource Sharing middleware.

## Getting Started

1.  **Clone the Repository:**

    ```bash
    git clone <repository-url>
    cd user-authentication-system
    ```

2.  **Install Dependencies:**

    ```bash
    npm install
    ```

3.  **Set Up Environment Variables:**

    * Create a `.env` file in the project root directory.
    * Add the following variables:

        ```
        PORT=3000
        MONGODB_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/<database>?retryWrites=true&w=majority
        JWT_SECRET=<your-secret-key>
        ```

        * Replace `<username>`, `<password>`, `<cluster>`, `<database>`, and `<your-secret-key>` with your actual values.

4.  **Start the Server:**

    ```bash
    npm run dev
    ```

    * The server will start on `http://localhost:3000`.

5.  **Run Tests (Optional):**

    ```bash
    npm test
    ```

## API Endpoints

* **POST /api/auth/register:** Register a new user.
* **POST /api/auth/login:** Log in and receive a JWT token.
* **GET /api/auth/protected:** Access a protected route (requires JWT).
* **POST /api/auth/reset-password-request:** Request a password reset.
* **POST /api/auth/reset-password/:token:** Reset the password using a token.

## Deployment

This application can be deployed to various platforms, including:

* **Vercel:**
    * Set up a Vercel account.
    * Login in to your vercel account
    * Connect your account with github account and import the project you want to deploy.
    * After importing the project please make sure to add variable in that that are present in .env file.
    * **Important Note:**
        * Vercel is best for serverless functions, so for a full node.js server, another platform is recommended.
        * If restructuring the project for serverless functions, connect your Git repository to Vercel and set environment variables. 

## Security Considerations

* **HTTPS:** Use HTTPS in production.
* **Rate Limiting:** Implement rate limiting to prevent brute-force attacks.
* **Input Sanitization:** Sanitize user inputs to prevent injection attacks.
* **Secure Password Storage:** Uses `bcryptjs` for password hashing.
* **JWT Security:** Keep your JWT secret secure.
* **CORS:** Configure CORS to restrict cross-origin requests.
* **Helmet:** Use the helmet middleware to add security headers.
* **Database Security:** Use strong authentication and restrict network access to the database.

## Testing

* Use Postman