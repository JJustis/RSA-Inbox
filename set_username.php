<?php
// Start session and set headers for JSON response
session_start();
header('Content-Type: application/json');

// Database connection parameters
$servername = "localhost";
$dbusername = "root";          // Replace with your database username
$dbpassword = "";              // Replace with your database password
$dbname = "secure_messaging";  // Replace with your database name

// Connect to the database
$conn = new mysqli($servername, $dbusername, $dbpassword, $dbname);

// Check database connection
if ($conn->connect_error) {
    echo json_encode(["status" => "error", "message" => "Database connection failed: " . $conn->connect_error]);
    exit();
}

// Handle POST request for username and public key storage
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);

    if (isset($input['username']) && !empty($input['username']) && isset($input['publicKey']) && !empty($input['publicKey'])) {
        $username = $conn->real_escape_string($input['username']);
        $publicKey = $conn->real_escape_string($input['publicKey']);

        // Set session username
        $_SESSION['username'] = $username;

        // Check if the username already exists in the database
        $checkUserStmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $checkUserStmt->bind_param("s", $username);
        $checkUserStmt->execute();
        $checkUserStmt->store_result();

        if ($checkUserStmt->num_rows > 0) {
            // Username already exists, return an error
            $response = ['status' => 'error', 'message' => 'Username already exists. Please choose a different username.'];
        } else {
            // Insert new user into the database
            $stmt = $conn->prepare("INSERT INTO users (username, public_key) VALUES (?, ?)");
            $stmt->bind_param("ss", $username, $publicKey);

            if ($stmt->execute()) {
                $response = ['status' => 'success', 'message' => 'Username set successfully and user registered in the database.'];
            } else {
                $response = ['status' => 'error', 'message' => 'Failed to register user: ' . $stmt->error];
            }
            $stmt->close();
        }

        $checkUserStmt->close();
    } else {
        $response = ['status' => 'error', 'message' => 'Invalid username or publicKey not provided.'];
    }
} else {
    $response = ['status' => 'error', 'message' => 'Invalid request method.'];
}

// Send JSON response
echo json_encode($response);
$conn->close();
?>
