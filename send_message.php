<?php
session_start();
header('Content-Type: application/json');

// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Log all errors for debugging
error_log("Request received for send_message.php");

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
    $sender_username = $_SESSION['username'];
    $input = json_decode(file_get_contents('php://input'), true);

    // Log the received input data
    error_log("Received input data: " . print_r($input, true));

    if (isset($input['recipient']) && isset($input['message'])) {
        $recipient_username = $conn->real_escape_string($input['recipient']);
        $encrypted_message = $conn->real_escape_string($input['message']);  // This is the encrypted message

        // Optional: Retrieve sender_id and recipient_id from users table
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $sender_username);
        $stmt->execute();
        $stmt->bind_result($sender_id);
        $stmt->fetch();
        $stmt->close();

        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $recipient_username);
        $stmt->execute();
        $stmt->bind_result($recipient_id);
        $stmt->fetch();
        $stmt->close();

        // Log the sender_id and recipient_id for debugging
        error_log("Sender ID: $sender_id, Recipient ID: $recipient_id");

        // Insert message into the database
        $stmt = $conn->prepare("INSERT INTO messages (sender_id, recipient_id, sender_username, recipient_username, encrypted_message, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
        if (!$stmt) {
            error_log("Prepare statement failed: " . $conn->error);
            echo json_encode(["status" => "error", "message" => "Prepare statement failed: " . $conn->error]);
            exit();
        }

        $stmt->bind_param("iisss", $sender_id, $recipient_id, $sender_username, $recipient_username, $encrypted_message);
        if ($stmt->execute()) {
            echo json_encode(["status" => "success", "message" => "Message sent successfully."]);
        } else {
            error_log("Failed to send message: " . $stmt->error);
            echo json_encode(["status" => "error", "message" => "Failed to send message: " . $stmt->error]);
        }

        $stmt->close();
    } else {
        error_log("Invalid recipient or message not provided.");
        echo json_encode(["status" => "error", "message" => "Invalid recipient or message not provided."]);
    }
} else {
    error_log("User not logged in.");
    echo json_encode(["status" => "error", "message" => "User not logged in."]);
}

$conn->close();
?>
