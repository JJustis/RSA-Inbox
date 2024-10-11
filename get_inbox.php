<?php
session_start();
header('Content-Type: application/json');

// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Log all errors to the error log for debugging
error_log("Request received for get_inbox.php");

// Database connection parameters
$servername = "localhost";
$dbusername = "root";          // Replace with your database username
$dbpassword = "";              // Replace with your database password
$dbname = "secure_messaging";  // Replace with your database name

// Connect to the database
$conn = new mysqli($servername, $dbusername, $dbpassword, $dbname);

// Check database connection
if ($conn->connect_error) {
    error_log("Database connection failed: " . $conn->connect_error);
    echo json_encode(["status" => "error", "message" => "Database connection failed: " . $conn->connect_error]);
    exit();
}

// Check if user is logged in
if (isset($_SESSION['username'])) {
    $username = $_SESSION['username'];

    // Log the username for debugging purposes
    error_log("Fetching messages for username: $username");

    // Prepare the SQL query to retrieve messages for the logged-in user based on recipient_username
    // Make sure to match the column names exactly as they are in the database
    $stmt = $conn->prepare("SELECT sender_username, encrypted_message, created_at FROM messages WHERE recipient_username = ?");
    
    if (!$stmt) {
        // Log the error returned by the prepare statement
        error_log("Prepare statement failed: " . $conn->error);
        echo json_encode(["status" => "error", "message" => "Database query failed: " . $conn->error]);
        exit();
    }

    // Bind the username parameter to the SQL query
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    $messages = [];
    while ($row = $result->fetch_assoc()) {
        $messages[] = [
            'sender' => $row['sender_username'],          // Adjusted to match the sender_username column
            'message' => $row['encrypted_message'],       // Adjusted to match the encrypted_message column
            'timestamp' => $row['created_at']             // Adjusted to match the created_at column
        ];
    }

    echo json_encode(["status" => "success", "messages" => $messages]);
    $stmt->close();
} else {
    error_log("User not logged in.");
    echo json_encode(["status" => "error", "message" => "User not logged in."]);
}

$conn->close();
?>
