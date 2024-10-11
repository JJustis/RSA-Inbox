<?php
header('Content-Type: application/json');

// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Log any PHP errors to a file or display them
error_log("Request received for get_public_key.php");

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

// Check if the username parameter is provided
if (isset($_GET['username']) && !empty($_GET['username'])) {
    $username = $conn->real_escape_string($_GET['username']);
    error_log("Fetching public key for username: $username");

    // Retrieve the public key for the given username
    $stmt = $conn->prepare("SELECT public_key FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->bind_result($publicKey);
    $stmt->fetch();

    if ($publicKey) {
        // Return the public key in JSON format
        echo json_encode(["status" => "success", "publicKey" => $publicKey]);
    } else {
        error_log("User not found for username: $username");
        echo json_encode(["status" => "error", "message" => "User not found"]);
    }

    $stmt->close();
} else {
    error_log("Invalid or missing username parameter.");
    echo json_encode(["status" => "error", "message" => "Invalid or missing username parameter."]);
}

$conn->close();
?>
