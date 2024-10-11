<?php
// Set headers for JSON response
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

// Retrieve public key roster
$sql = "SELECT username, public_key FROM users";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    $publicKeys = [];
    while ($row = $result->fetch_assoc()) {
        $publicKeys[] = ['username' => $row['username'], 'publicKey' => $row['public_key']];
    }
    echo json_encode(["status" => "success", "publicKeys" => $publicKeys]);
} else {
    echo json_encode(["status" => "success", "publicKeys" => []]);  // No public keys found
}

$conn->close();
?>
