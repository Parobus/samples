# Node.js App with Ngrok Setup

This repository contains a simple Node.js app that you can use to set up a webhook. Ngrok is used to create a public URL for your local development environment, allowing you to receive webhook events.

## Prerequisites

Make sure you have the following installed on your machine:

- [Node.js](https://nodejs.org/)
- [npm](https://www.npmjs.com/get-npm)
- [Ngrok](https://ngrok.com/)

## Installation

1. Clone this repository:

    ```bash
    git clone https://github.com/Parobus/samples
    ```

2. Navigate to the project directory:

    ```bash
    cd node-js-webhooks-api
    ```

3. Install the required npm packages:

    ```bash
    npm install
    ```

## Usage

1. Run the Node.js app:

    ```bash
    node app.js
    ```

   This will start your Node.js server on port 5069.

2. Open a new terminal window and run Ngrok to create a public URL:

    ```bash
    ngrok http 5069
    ```

   Ngrok will generate a public URL (e.g., `https://your-ngrok-subdomain.ngrok.io`). Keep this URL handy.

3. Create a new webhook:

   - Go to MBT API to set up the webhook.
   - Create a new webhook and paste the Ngrok URL followed by `/webhook` (e.g., `https://your-ngrok-subdomain.ngrok.io/webhook`).

4. You should get webhook messages.
