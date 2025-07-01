<?php
// MHCN+ - Modern Hybrid Social Network
// Single-file PHP application with HTML, CSS, JS, and PHP

// Error reporting for development
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Start session
session_start();

// Configuration
define('MAX_POST_LENGTH', 450);
define('MAX_IMAGE_SIZE', 1048576); // 1MB in bytes
define('POST_LIFETIME', 7 * 24 * 60 * 60); // 7 days in seconds
define('REPORT_THRESHOLD', 5);
define('AES_KEY', 'MHCN+_SecureKey_256bit'); // In production, use a more secure key
define('AES_IV', '1234567890123456'); // 16 bytes IV for AES-256-CBC

// Categories
$categories = ['gaming', 'science', 'sports', 'news', 'lifestyle', 'programming'];

// Blacklist for moderation
$blacklist = ['fuck', 'shit', 'asshole', 'bitch', 'cunt', 'nigger', 'retard', 'fag', 'whore', 'slut'];

// Create necessary directories if they don't exist
if (!file_exists('plusfiles')) {
    mkdir('plusfiles', 0755, true);
}
if (!file_exists('plususers')) {
    mkdir('plususers', 0755, true);
}

// Helper functions
function encryptData($data) {
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', AES_KEY, 0, AES_IV);
    return base64_encode($encrypted);
}

function decryptData($data) {
    $decoded = base64_decode($data);
    return openssl_decrypt($decoded, 'aes-256-cbc', AES_KEY, 0, AES_IV);
}

function sanitizeInput($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

function generateRandomId($length = 16) {
    return bin2hex(random_bytes($length));
}

function compressImage($source, $destination, $quality) {
    $info = getimagesize($source);
    
    if ($info['mime'] == 'image/jpeg') {
        $image = imagecreatefromjpeg($source);
        imagejpeg($image, $destination, $quality);
    } elseif ($info['mime'] == 'image/png') {
        $image = imagecreatefrompng($source);
        imagepng($image, $destination, 9, PNG_ALL_FILTERS);
    } elseif ($info['mime'] == 'image/gif') {
        $image = imagecreatefromgif($source);
        imagegif($image, $destination);
    }
    
    return filesize($destination);
}

function checkBlacklist($text) {
    global $blacklist;
    foreach ($blacklist as $word) {
        if (stripos($text, $word) !== false) {
            return true;
        }
    }
    return false;
}

function cleanOldPosts() {
    $postsFile = 'posts.json';
    if (file_exists($postsFile)) {
        $encrypted = file_get_contents($postsFile);
        $json = decryptData($encrypted);
        $posts = json_decode($json, true) ?: [];
        
        $currentTime = time();
        $updatedPosts = [];
        
        foreach ($posts as $post) {
            if ($currentTime - $post['timestamp'] < POST_LIFETIME) {
                $updatedPosts[] = $post;
            } else {
                // Delete associated image if exists
                if (!empty($post['image']) && file_exists('plusfiles/' . $post['image'])) {
                    unlink('plusfiles/' . $post['image']);
                }
            }
        }
        
        if (count($posts) != count($updatedPosts)) {
            $encrypted = encryptData(json_encode($updatedPosts));
            file_put_contents($postsFile, $encrypted);
        }
    }
}

function getUserFilePath($username) {
    return 'plususers/' . md5($username) . '.json';
}

function getUserData($username) {
    $filePath = getUserFilePath($username);
    if (file_exists($filePath)) {
        $encrypted = file_get_contents($filePath);
        $json = decryptData($encrypted);
        return json_decode($json, true);
    }
    return null;
}

function saveUserData($username, $data) {
    $filePath = getUserFilePath($username);
    $encrypted = encryptData(json_encode($data));
    file_put_contents($filePath, $encrypted);
}

function getCurrentUser() {
    if (isset($_SESSION['username'])) {
        return getUserData($_SESSION['username']);
    }
    return null;
}

function savePost($post) {
    $postsFile = 'posts.json';
    $posts = [];
    
    if (file_exists($postsFile)) {
        $encrypted = file_get_contents($postsFile);
        $json = decryptData($encrypted);
        $posts = json_decode($json, true) ?: [];
    }
    
    $posts[] = $post;
    $encrypted = encryptData(json_encode($posts));
    file_put_contents($postsFile, $encrypted);
}

function getPosts($filter = null) {
    $postsFile = 'posts.json';
    if (!file_exists($postsFile)) {
        return [];
    }
    
    $encrypted = file_get_contents($postsFile);
    $json = decryptData($encrypted);
    $posts = json_decode($json, true) ?: [];
    
    // Sort by timestamp (newest first)
    usort($posts, function($a, $b) {
        return $b['timestamp'] - $a['timestamp'];
    });
    
    if ($filter === 'trending') {
        // Sort by likes (most liked first)
        usort($posts, function($a, $b) {
            $scoreA = count($a['likes']) * 0.6 + ($a['timestamp'] / time()) * 0.4;
            $scoreB = count($b['likes']) * 0.6 + ($b['timestamp'] / time()) * 0.4;
            return $scoreB <=> $scoreA;
        });
    }
    
    return $posts;
}

function getReportedPosts() {
    $reportedFile = 'reported.json';
    if (!file_exists($reportedFile)) {
        return [];
    }
    
    $encrypted = file_get_contents($reportedFile);
    $json = decryptData($encrypted);
    return json_decode($json, true) ?: [];
}

function reportPost($postId) {
    $postsFile = 'posts.json';
    if (!file_exists($postsFile)) {
        return false;
    }
    
    $encrypted = file_get_contents($postsFile);
    $json = decryptData($encrypted);
    $posts = json_decode($json, true) ?: [];
    
    $updated = false;
    $reportedPost = null;
    
    foreach ($posts as &$post) {
        if ($post['id'] === $postId) {
            if (!isset($post['reports'])) {
                $post['reports'] = [];
            }
            
            // Prevent duplicate reports from same user
            if (isset($_SESSION['username']) && !in_array($_SESSION['username'], $post['reports'])) {
                $post['reports'][] = $_SESSION['username'];
                $updated = true;
                
                // If reached threshold, add to reported posts
                if (count($post['reports']) >= REPORT_THRESHOLD) {
                    $reportedPost = $post;
                }
            }
            break;
        }
    }
    
    if ($updated) {
        $encrypted = encryptData(json_encode($posts));
        file_put_contents($postsFile, $encrypted);
    }
    
    if ($reportedPost) {
        $reportedFile = 'reported.json';
        $reportedPosts = getReportedPosts();
        $reportedPosts[] = $reportedPost;
        $encrypted = encryptData(json_encode($reportedPosts));
        file_put_contents($reportedFile, $encrypted);
    }
    
    return $updated;
}

function likePost($postId, $username) {
    $postsFile = 'posts.json';
    if (!file_exists($postsFile)) {
        return false;
    }
    
    $encrypted = file_get_contents($postsFile);
    $json = decryptData($encrypted);
    $posts = json_decode($json, true) ?: [];
    
    $updated = false;
    
    foreach ($posts as &$post) {
        if ($post['id'] === $postId) {
            if (!isset($post['likes'])) {
                $post['likes'] = [];
            }
            
            // Toggle like
            $index = array_search($username, $post['likes']);
            if ($index === false) {
                $post['likes'][] = $username;
            } else {
                array_splice($post['likes'], $index, 1);
            }
            
            $updated = true;
            break;
        }
    }
    
    if ($updated) {
        $encrypted = encryptData(json_encode($posts));
        file_put_contents($postsFile, $encrypted);
    }
    
    return $updated;
}

function addComment($postId, $username, $comment) {
    $postsFile = 'posts.json';
    if (!file_exists($postsFile)) {
        return false;
    }
    
    $encrypted = file_get_contents($postsFile);
    $json = decryptData($encrypted);
    $posts = json_decode($json, true) ?: [];
    
    $updated = false;
    
    foreach ($posts as &$post) {
        if ($post['id'] === $postId) {
            if (!isset($post['comments'])) {
                $post['comments'] = [];
            }
            
            $post['comments'][] = [
                'id' => generateRandomId(),
                'username' => $username,
                'text' => $comment,
                'timestamp' => time()
            ];
            
            $updated = true;
            break;
        }
    }
    
    if ($updated) {
        $encrypted = encryptData(json_encode($posts));
        file_put_contents($postsFile, $encrypted);
    }
    
    return $updated;
}

// Clean old posts on each request
cleanOldPosts();

// Handle form submissions
$action = $_POST['action'] ?? '';
$error = '';
$success = '';

if ($action === 'register') {
    $username = sanitizeInput($_POST['username'] ?? '');
    $email = sanitizeInput($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $birthdate = sanitizeInput($_POST['birthdate'] ?? '');
    $bio = sanitizeInput($_POST['bio'] ?? '');
    $inactiveDays = intval($_POST['inactive_days'] ?? 30);
    $posthumousLetter = sanitizeInput($_POST['posthumous_letter'] ?? '');
    $targetCategories = $_POST['target_categories'] ?? [];
    
    // Validate
    if (empty($username) || empty($email) || empty($password) || empty($confirmPassword) || empty($birthdate)) {
        $error = 'All fields are required except bio and posthumous letter.';
    } elseif ($password !== $confirmPassword) {
        $error = 'Passwords do not match.';
    } elseif (strlen($password) < 8) {
        $error = 'Password must be at least 8 characters long.';
    } elseif (file_exists(getUserFilePath($username))) {
        $error = 'Username already taken.';
    } else {
        // Save user
        $userData = [
            'username' => $username,
            'email' => $email,
            'password' => password_hash($password, PASSWORD_BCRYPT),
            'birthdate' => $birthdate,
            'bio' => $bio,
            'inactive_days' => $inactiveDays,
            'posthumous_letter' => $posthumousLetter,
            'target_categories' => $targetCategories,
            'last_active' => time(),
            'joined' => time()
        ];
        
        saveUserData($username, $userData);
        $_SESSION['username'] = $username;
        $success = 'Registration successful!';
    }
} elseif ($action === 'login') {
    $username = sanitizeInput($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    $userData = getUserData($username);
    
    if ($userData && password_verify($password, $userData['password'])) {
        $_SESSION['username'] = $username;
        // Update last active time
        $userData['last_active'] = time();
        saveUserData($username, $userData);
        $success = 'Login successful!';
    } else {
        $error = 'Invalid username or password.';
    }
} elseif ($action === 'logout') {
    session_destroy();
    header('Location: '.$_SERVER['PHP_SELF']);
    exit;
} elseif ($action === 'create_post' && isset($_SESSION['username'])) {
    $title = sanitizeInput($_POST['title'] ?? '');
    $content = sanitizeInput($_POST['content'] ?? '');
    $category = sanitizeInput($_POST['category'] ?? '');
    
    if (empty($title) || empty($content) || empty($category)) {
        $error = 'Title, content, and category are required.';
    } elseif (strlen($content) > MAX_POST_LENGTH) {
        $error = 'Post content exceeds maximum length of '.MAX_POST_LENGTH.' characters.';
    } elseif (checkBlacklist($title) || checkBlacklist($content)) {
        $error = 'Your post contains inappropriate language.';
    } else {
        $imagePath = '';
        
        // Handle image upload
        if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
            $file = $_FILES['image'];
            $fileType = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            $allowedTypes = ['jpg', 'jpeg', 'png', 'gif'];
            
            if (in_array($fileType, $allowedTypes)) {
                if ($file['size'] <= MAX_IMAGE_SIZE) {
                    $imageName = generateRandomId() . '.' . $fileType;
                    move_uploaded_file($file['tmp_name'], 'plusfiles/' . $imageName);
                    $imagePath = $imageName;
                } else {
                    // Try to compress
                    $imageName = generateRandomId() . '.' . $fileType;
                    $quality = 80; // Start with 80% quality
                    $compressedSize = compressImage($file['tmp_name'], 'plusfiles/' . $imageName, $quality);
                    
                    if ($compressedSize <= MAX_IMAGE_SIZE) {
                        $imagePath = $imageName;
                    } else {
                        // Try lower quality
                        $quality = 60;
                        $compressedSize = compressImage($file['tmp_name'], 'plusfiles/' . $imageName, $quality);
                        
                        if ($compressedSize <= MAX_IMAGE_SIZE) {
                            $imagePath = $imageName;
                        } else {
                            unlink('plusfiles/' . $imageName);
                            $error = 'Image is too large even after compression.';
                        }
                    }
                }
            } else {
                $error = 'Only JPG, PNG, and GIF images are allowed.';
            }
        }
        
        if (empty($error)) {
            $post = [
                'id' => generateRandomId(),
                'username' => $_SESSION['username'],
                'title' => $title,
                'content' => $content,
                'category' => $category,
                'image' => $imagePath,
                'timestamp' => time(),
                'likes' => [],
                'comments' => [],
                'reports' => []
            ];
            
            savePost($post);
            $success = 'Post created successfully!';
        }
    }
} elseif ($action === 'like_post' && isset($_SESSION['username'])) {
    $postId = sanitizeInput($_POST['post_id'] ?? '');
    if (!empty($postId)) {
        likePost($postId, $_SESSION['username']);
    }
} elseif ($action === 'report_post' && isset($_SESSION['username'])) {
    $postId = sanitizeInput($_POST['post_id'] ?? '');
    if (!empty($postId)) {
        reportPost($postId);
        $success = 'Post reported. Thank you for keeping MHCN+ safe.';
    }
} elseif ($action === 'add_comment' && isset($_SESSION['username'])) {
    $postId = sanitizeInput($_POST['post_id'] ?? '');
    $comment = sanitizeInput($_POST['comment'] ?? '');
    
    if (!empty($postId) && !empty($comment)) {
        if (checkBlacklist($comment)) {
            $error = 'Your comment contains inappropriate language.';
        } else {
            addComment($postId, $_SESSION['username'], $comment);
            $success = 'Comment added!';
        }
    }
}

// Get current user
$currentUser = getCurrentUser();

// Update last active time if logged in
if ($currentUser) {
    $currentUser['last_active'] = time();
    saveUserData($currentUser['username'], $currentUser);
}

// Get posts for feed
$feedType = $_GET['feed'] ?? 'foryou';
$posts = getPosts($feedType === 'trending' ? 'trending' : null);

// Search functionality
$searchQuery = $_GET['search'] ?? '';
$searchResults = [];
if (!empty($searchQuery)) {
    $searchQuery = sanitizeInput($searchQuery);
    foreach ($posts as $post) {
        if (stripos($post['title'], $searchQuery) !== false || 
            stripos($post['content'], $searchQuery) !== false || 
            stripos($post['username'], $searchQuery) !== false) {
            $searchResults[] = $post;
        }
    }
}

// Check if viewing a profile
$profileUser = null;
if (isset($_GET['profile'])) {
    $profileUsername = sanitizeInput($_GET['profile']);
    $profileUser = getUserData($profileUsername);
}

// Check if user is inactive (dead)
$isUserDead = false;
if ($profileUser) {
    $inactiveThreshold = $profileUser['inactive_days'] * 24 * 60 * 60;
    $isUserDead = (time() - $profileUser['last_active']) > $inactiveThreshold;
}
?>
<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MHCN+ - Modern Hybrid Social Network</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: '#6d28d9',
                        secondary: '#10b981',
                        dark: '#1e293b',
                        darker: '#0f172a',
                        accent: '#f59e0b',
                    },
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                        mono: ['Fira Code', 'monospace'],
                    },
                }
            }
        }
    </script>
    <style>
        .gradient-bg {
            background: linear-gradient(135deg, #6d28d9 0%, #10b981 100%);
        }
        .post-content a {
            color: #6d28d9;
            text-decoration: underline;
        }
        .post-content pre {
            background-color: #1e293b;
            color: #f8fafc;
            padding: 1rem;
            border-radius: 0.5rem;
            overflow-x: auto;
            margin: 1rem 0;
        }
        .post-content code {
            background-color: #1e293b;
            color: #f8fafc;
            padding: 0.2rem 0.4rem;
            border-radius: 0.25rem;
            font-family: 'Fira Code', monospace;
        }
        .post-content h1, .post-content h2, .post-content h3 {
            font-weight: bold;
            margin: 1rem 0 0.5rem 0;
        }
        .post-content h1 { font-size: 1.5rem; }
        .post-content h2 { font-size: 1.25rem; }
        .post-content h3 { font-size: 1.1rem; }
        .post-content ul, .post-content ol {
            margin-left: 1.5rem;
            margin-bottom: 1rem;
        }
        .post-content ul { list-style-type: disc; }
        .post-content ol { list-style-type: decimal; }
        .post-content blockquote {
            border-left: 4px solid #6d28d9;
            padding-left: 1rem;
            margin: 1rem 0;
            color: #64748b;
        }
    </style>
</head>
<body class="bg-gray-100 dark:bg-darker text-gray-900 dark:text-gray-100 min-h-screen font-sans">
    <!-- Header -->
    <header class="gradient-bg text-white shadow-lg">
        <div class="container mx-auto px-4 py-4 flex justify-between items-center">
            <div class="flex items-center space-x-2">
                <i class="fas fa-rocket text-2xl"></i>
                <h1 class="text-2xl font-bold">MHCN+</h1>
            </div>
            
            <div class="flex items-center space-x-4">
                <?php if ($currentUser): ?>
                    <div class="relative">
                        <button id="user-menu-btn" class="flex items-center space-x-2 focus:outline-none">
                            <img src="https://ui-avatars.com/api/?name=<?= urlencode($currentUser['username']) ?>&background=6d28d9&color=fff" 
                                 alt="Profile" class="w-8 h-8 rounded-full">
                            <span class="hidden md:inline"><?= htmlspecialchars($currentUser['username']) ?></span>
                            <i class="fas fa-chevron-down text-xs"></i>
                        </button>
                        <div id="user-menu" class="absolute right-0 mt-2 w-48 bg-white dark:bg-dark rounded-md shadow-lg py-1 z-50 hidden">
                            <a href="?profile=<?= urlencode($currentUser['username']) ?>" class="block px-4 py-2 text-gray-800 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700">Profile</a>
                            <a href="?settings" class="block px-4 py-2 text-gray-800 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700">Settings</a>
                            <form method="post" class="block px-4 py-2 text-gray-800 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700">
                                <input type="hidden" name="action" value="logout">
                                <button type="submit" class="w-full text-left">Logout</button>
                            </form>
                        </div>
                    </div>
                <?php else: ?>
                    <a href="#login" class="px-4 py-2 bg-white text-primary rounded-full font-medium hover:bg-opacity-90 transition">Login</a>
                <?php endif; ?>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <main class="container mx-auto px-4 py-8 flex flex-col lg:flex-row gap-8">
        <!-- Sidebar -->
        <aside class="lg:w-1/4 space-y-6">
            <?php if ($currentUser): ?>
                <!-- Create Post Card -->
                <div class="bg-white dark:bg-dark rounded-xl shadow-md p-6">
                    <h2 class="text-xl font-bold mb-4">Create Post</h2>
                    <form method="post" enctype="multipart/form-data">
                        <input type="hidden" name="action" value="create_post">
                        <div class="mb-4">
                            <label for="title" class="block text-sm font-medium mb-1">Title</label>
                            <input type="text" id="title" name="title" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800" required>
                        </div>
                        <div class="mb-4">
                            <label for="category" class="block text-sm font-medium mb-1">Category</label>
                            <select id="category" name="category" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800" required>
                                <?php foreach ($categories as $cat): ?>
                                    <option value="<?= htmlspecialchars($cat) ?>"><?= ucfirst(htmlspecialchars($cat)) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="mb-4">
                            <label for="content" class="block text-sm font-medium mb-1">Content</label>
                            <textarea id="content" name="content" rows="4" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800" required maxlength="<?= MAX_POST_LENGTH ?>"></textarea>
                            <div class="text-xs text-gray-500 mt-1">Max <?= MAX_POST_LENGTH ?> characters</div>
                        </div>
                        <div class="mb-4">
                            <label for="image" class="block text-sm font-medium mb-1">Image/GIF (optional, max 1MB)</label>
                            <input type="file" id="image" name="image" accept="image/jpeg,image/png,image/gif" class="w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-primary file:text-white hover:file:bg-primary-dark">
                        </div>
                        <div class="flex justify-between items-center">
                            <div class="text-xs text-gray-500">
                                <span id="formatting-help" class="cursor-pointer text-primary hover:underline">Formatting help</span>
                            </div>
                            <button type="submit" class="px-4 py-2 bg-primary text-white rounded-md hover:bg-primary-dark transition">Post</button>
                        </div>
                    </form>
                </div>
            <?php endif; ?>

            <!-- Categories -->
            <div class="bg-white dark:bg-dark rounded-xl shadow-md p-6">
                <h2 class="text-xl font-bold mb-4">Categories</h2>
                <div class="space-y-2">
                    <a href="?feed=foryou" class="block px-3 py-2 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 transition <?= ($feedType === 'foryou') ? 'bg-gray-100 dark:bg-gray-700 font-medium' : '' ?>">
                        <i class="fas fa-heart mr-2 text-primary"></i> For You
                    </a>
                    <a href="?feed=trending" class="block px-3 py-2 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 transition <?= ($feedType === 'trending') ? 'bg-gray-100 dark:bg-gray-700 font-medium' : '' ?>">
                        <i class="fas fa-fire mr-2 text-accent"></i> Trending
                    </a>
                    <?php foreach ($categories as $cat): ?>
                        <a href="?category=<?= urlencode($cat) ?>" class="block px-3 py-2 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                            <i class="fas fa-<?= 
                                $cat === 'gaming' ? 'gamepad' : 
                                ($cat === 'science' ? 'flask' : 
                                ($cat === 'sports' ? 'running' : 
                                ($cat === 'news' ? 'newspaper' : 
                                ($cat === 'lifestyle' ? 'spa' : 'code')))) 
                            ?> mr-2"></i> <?= ucfirst(htmlspecialchars($cat)) ?>
                        </a>
                    <?php endforeach; ?>
                </div>
            </div>

            <!-- Online Users -->
            <?php if ($currentUser): ?>
                <div class="bg-white dark:bg-dark rounded-xl shadow-md p-6">
                    <h2 class="text-xl font-bold mb-4">Online Now</h2>
                    <div class="space-y-3">
                        <?php 
                        // Simulating online users - in a real app you'd query active sessions
                        $onlineUsers = [];
                        $allUserFiles = glob('plususers/*.json');
                        shuffle($allUserFiles);
                        $sampleUsers = array_slice($allUserFiles, 0, 5);
                        
                        foreach ($sampleUsers as $userFile) {
                            $encrypted = file_get_contents($userFile);
                            $json = decryptData($encrypted);
                            $user = json_decode($json, true);
                            if ($user && $user['username'] !== $currentUser['username']) {
                                $onlineUsers[] = $user;
                            }
                        }
                        
                        foreach ($onlineUsers as $user): 
                        ?>
                            <a href="?profile=<?= urlencode($user['username']) ?>" class="flex items-center space-x-3 hover:bg-gray-100 dark:hover:bg-gray-700 p-2 rounded-md transition">
                                <img src="https://ui-avatars.com/api/?name=<?= urlencode($user['username']) ?>&background=6d28d9&color=fff" 
                                     alt="<?= htmlspecialchars($user['username']) ?>" class="w-8 h-8 rounded-full">
                                <span><?= htmlspecialchars($user['username']) ?></span>
                                <span class="w-2 h-2 bg-green-500 rounded-full ml-auto"></span>
                            </a>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>
        </aside>

        <!-- Main Feed -->
        <div class="lg:w-2/4 space-y-6">
            <?php if (!empty($error)): ?>
                <div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 rounded-md">
                    <p><?= htmlspecialchars($error) ?></p>
                </div>
            <?php endif; ?>
            
            <?php if (!empty($success)): ?>
                <div class="bg-green-100 border-l-4 border-green-500 text-green-700 p-4 rounded-md">
                    <p><?= htmlspecialchars($success) ?></p>
                </div>
            <?php endif; ?>
            
            <?php if ($profileUser): ?>
                <!-- Profile View -->
                <div class="bg-white dark:bg-dark rounded-xl shadow-md overflow-hidden">
                    <!-- Profile Banner -->
                    <div class="gradient-bg h-32"></div>
                    
                    <!-- Profile Content -->
                    <div class="px-6 pb-6 relative">
                        <div class="flex justify-between items-start">
                            <div class="flex items-end -mt-16 space-x-4">
                                <img src="https://ui-avatars.com/api/?name=<?= urlencode($profileUser['username']) ?>&background=6d28d9&color=fff" 
                                     alt="<?= htmlspecialchars($profileUser['username']) ?>" class="w-24 h-24 rounded-full border-4 border-white dark:border-dark">
                                <div>
                                    <h2 class="text-2xl font-bold"><?= htmlspecialchars($profileUser['username']) ?></h2>
                                    <p class="text-gray-500">Joined <?= date('M Y', $profileUser['joined']) ?></p>
                                </div>
                            </div>
                            
                            <?php if ($currentUser && $currentUser['username'] === $profileUser['username']): ?>
                                <a href="?settings" class="px-4 py-2 bg-primary text-white rounded-md hover:bg-primary-dark transition">Edit Profile</a>
                            <?php endif; ?>
                        </div>
                        
                        <div class="mt-6">
                            <?php if ($isUserDead): ?>
                                <div class="bg-gray-100 dark:bg-gray-800 p-6 rounded-lg border-l-4 border-gray-500">
                                    <h3 class="text-xl font-bold mb-2">In Memoriam</h3>
                                    <p class="text-gray-700 dark:text-gray-300">This user has been inactive for more than <?= $profileUser['inactive_days'] ?> days.</p>
                                    <div class="mt-4 p-4 bg-white dark:bg-gray-700 rounded-md">
                                        <p class="italic">"<?= htmlspecialchars($profileUser['posthumous_letter']) ?>"</p>
                                    </div>
                                </div>
                            <?php else: ?>
                                <h3 class="text-lg font-semibold mb-2">About</h3>
                                <p class="text-gray-700 dark:text-gray-300"><?= !empty($profileUser['bio']) ? htmlspecialchars($profileUser['bio']) : 'This user has not written a bio yet.' ?></p>
                                
                                <div class="mt-4 grid grid-cols-2 gap-4">
                                    <div>
                                        <h4 class="text-sm font-medium text-gray-500">Categories</h4>
                                        <ul class="mt-1 space-y-1">
                                            <?php foreach ($profileUser['target_categories'] as $cat): ?>
                                                <li class="flex items-center">
                                                    <i class="fas fa-<?= 
                                                        $cat === 'gaming' ? 'gamepad' : 
                                                        ($cat === 'science' ? 'flask' : 
                                                        ($cat === 'sports' ? 'running' : 
                                                        ($cat === 'news' ? 'newspaper' : 
                                                        ($cat === 'lifestyle' ? 'spa' : 'code')))) 
                                                    ?> mr-2 text-primary"></i>
                                                    <?= ucfirst(htmlspecialchars($cat)) ?>
                                                </li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                    <div>
                                        <h4 class="text-sm font-medium text-gray-500">Activity</h4>
                                        <p class="mt-1">Last active: <?= date('M j, Y', $profileUser['last_active']) ?></p>
                                        <p>Inactive threshold: <?= $profileUser['inactive_days'] ?> days</p>
                                    </div>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
                
                <!-- User's Posts -->
                <h3 class="text-xl font-bold mt-8 mb-4">Posts</h3>
                <?php 
                $userPosts = array_filter($posts, function($post) use ($profileUser) {
                    return $post['username'] === $profileUser['username'];
                });
                
                if (empty($userPosts) && !$isUserDead): ?>
                    <div class="bg-white dark:bg-dark rounded-xl shadow-md p-6 text-center">
                        <p class="text-gray-500"><?= htmlspecialchars($profileUser['username']) ?> hasn't posted anything yet.</p>
                    </div>
                <?php elseif (!$isUserDead): ?>
                    <?php foreach ($userPosts as $post): ?>
                        <?php include 'post_card.php'; ?>
                    <?php endforeach; ?>
                <?php endif; ?>
                
            <?php elseif (!empty($searchQuery)): ?>
                <!-- Search Results -->
                <h2 class="text-2xl font-bold mb-6">Search Results for "<?= htmlspecialchars($searchQuery) ?>"</h2>
                
                <?php if (empty($searchResults)): ?>
                    <div class="bg-white dark:bg-dark rounded-xl shadow-md p-6 text-center">
                        <p class="text-gray-500">No results found for "<?= htmlspecialchars($searchQuery) ?>".</p>
                    </div>
                <?php else: ?>
                    <?php foreach ($searchResults as $post): ?>
                        <?php include 'post_card.php'; ?>
                    <?php endforeach; ?>
                <?php endif; ?>
                
            <?php else: ?>
                <!-- Regular Feed -->
                <h2 class="text-2xl font-bold mb-6"><?= $feedType === 'trending' ? 'Trending Now' : 'For You' ?></h2>
                
                <?php if (empty($posts)): ?>
                    <div class="bg-white dark:bg-dark rounded-xl shadow-md p-6 text-center">
                        <p class="text-gray-500">No posts yet. Be the first to post something!</p>
                    </div>
                <?php else: ?>
                    <?php foreach ($posts as $post): ?>
                        <?php include 'post_card.php'; ?>
                    <?php endforeach; ?>
                <?php endif; ?>
            <?php endif; ?>
        </div>

        <!-- Right Sidebar -->
        <aside class="lg:w-1/4 space-y-6">
            <!-- Search -->
            <div class="bg-white dark:bg-dark rounded-xl shadow-md p-6">
                <form method="get" class="relative">
                    <input type="text" name="search" placeholder="Search MHCN+" 
                           class="w-full px-4 py-2 pl-10 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800" 
                           value="<?= !empty($searchQuery) ? htmlspecialchars($searchQuery) : '' ?>">
                    <i class="fas fa-search absolute left-3 top-3 text-gray-400"></i>
                </form>
            </div>
            
            <!-- Trending Topics -->
            <div class="bg-white dark:bg-dark rounded-xl shadow-md p-6">
                <h2 class="text-xl font-bold mb-4">Trending Topics</h2>
                <div class="space-y-3">
                    <?php 
                    // Simulating trending topics
                    $trendingTopics = [
                        ['tag' => 'GameRelease', 'posts' => rand(100, 500)],
                        ['tag' => 'TechNews', 'posts' => rand(80, 400)],
                        ['tag' => 'ScienceDiscovery', 'posts' => rand(50, 300)],
                        ['tag' => 'SportsEvent', 'posts' => rand(70, 350)],
                        ['tag' => 'ProgrammingTips', 'posts' => rand(60, 250)],
                    ];
                    
                    // Sort by post count
                    usort($trendingTopics, function($a, $b) {
                        return $b['posts'] - $a['posts'];
                    });
                    
                    foreach ($trendingTopics as $topic): 
                    ?>
                        <a href="?search=<?= urlencode($topic['tag']) ?>" class="block hover:bg-gray-100 dark:hover:bg-gray-700 p-2 rounded-md transition">
                            <div class="flex justify-between items-center">
                                <span class="font-medium">#<?= htmlspecialchars($topic['tag']) ?></span>
                                <span class="text-sm text-gray-500"><?= $topic['posts'] ?> posts</span>
                            </div>
                        </a>
                    <?php endforeach; ?>
                </div>
            </div>
            
            <!-- Who to follow -->
            <?php if ($currentUser): ?>
                <div class="bg-white dark:bg-dark rounded-xl shadow-md p-6">
                    <h2 class="text-xl font-bold mb-4">Who to follow</h2>
                    <div class="space-y-4">
                        <?php 
                        // Simulating suggested users - in a real app you'd implement a recommendation algorithm
                        $suggestedUsers = [];
                        $allUserFiles = glob('plususers/*.json');
                        shuffle($allUserFiles);
                        $sampleUsers = array_slice($allUserFiles, 0, 3);
                        
                        foreach ($sampleUsers as $userFile) {
                            $encrypted = file_get_contents($userFile);
                            $json = decryptData($encrypted);
                            $user = json_decode($json, true);
                            if ($user && $user['username'] !== $currentUser['username']) {
                                $suggestedUsers[] = $user;
                            }
                        }
                        
                        foreach ($suggestedUsers as $user): 
                        ?>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <img src="https://ui-avatars.com/api/?name=<?= urlencode($user['username']) ?>&background=6d28d9&color=fff" 
                                         alt="<?= htmlspecialchars($user['username']) ?>" class="w-10 h-10 rounded-full">
                                    <div>
                                        <a href="?profile=<?= urlencode($user['username']) ?>" class="font-medium hover:underline"><?= htmlspecialchars($user['username']) ?></a>
                                        <p class="text-sm text-gray-500"><?= !empty($user['bio']) ? substr(htmlspecialchars($user['bio']), 0, 20) . (strlen($user['bio']) > 20 ? '...' : '') : 'MHCN+ User' ?></p>
                                    </div>
                                </div>
                                <button class="px-3 py-1 text-sm bg-gray-200 dark:bg-gray-700 rounded-full hover:bg-gray-300 dark:hover:bg-gray-600 transition">Follow</button>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>
            
            <!-- Login/Register Card (for guests) -->
            <?php if (!$currentUser): ?>
                <div class="bg-white dark:bg-dark rounded-xl shadow-md p-6" id="login">
                    <h2 class="text-xl font-bold mb-4">Join MHCN+</h2>
                    <p class="text-gray-600 dark:text-gray-300 mb-4">Connect with like-minded people and share your thoughts.</p>
                    
                    <!-- Login Form -->
                    <form method="post" class="mb-6">
                        <input type="hidden" name="action" value="login">
                        <div class="mb-4">
                            <label for="login_username" class="block text-sm font-medium mb-1">Username</label>
                            <input type="text" id="login_username" name="username" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800" required>
                        </div>
                        <div class="mb-4">
                            <label for="login_password" class="block text-sm font-medium mb-1">Password</label>
                            <input type="password" id="login_password" name="password" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800" required>
                        </div>
                        <button type="submit" class="w-full px-4 py-2 bg-primary text-white rounded-md hover:bg-primary-dark transition">Login</button>
                    </form>
                    
                    <div class="text-center mb-4">
                        <span class="text-sm text-gray-500">Don't have an account?</span>
                        <a href="#register" class="text-sm text-primary hover:underline ml-1">Register</a>
                    </div>
                </div>
                
                <!-- Register Form -->
                <div class="bg-white dark:bg-dark rounded-xl shadow-md p-6" id="register">
                    <h2 class="text-xl font-bold mb-4">Create Account</h2>
                    <form method="post">
                        <input type="hidden" name="action" value="register">
                        <div class="mb-4">
                            <label for="reg_username" class="block text-sm font-medium mb-1">Username</label>
                            <input type="text" id="reg_username" name="username" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800" required>
                        </div>
                        <div class="mb-4">
                            <label for="reg_email" class="block text-sm font-medium mb-1">Email</label>
                            <input type="email" id="reg_email" name="email" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800" required>
                        </div>
                        <div class="mb-4">
                            <label for="reg_password" class="block text-sm font-medium mb-1">Password</label>
                            <input type="password" id="reg_password" name="password" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800" required>
                        </div>
                        <div class="mb-4">
                            <label for="reg_confirm_password" class="block text-sm font-medium mb-1">Confirm Password</label>
                            <input type="password" id="reg_confirm_password" name="confirm_password" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800" required>
                        </div>
                        <div class="mb-4">
                            <label for="reg_birthdate" class="block text-sm font-medium mb-1">Birthdate</label>
                            <input type="date" id="reg_birthdate" name="birthdate" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800" required>
                        </div>
                        <div class="mb-4">
                            <label for="reg_bio" class="block text-sm font-medium mb-1">Biography (optional)</label>
                            <textarea id="reg_bio" name="bio" rows="2" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800"></textarea>
                        </div>
                        <div class="mb-4">
                            <label for="reg_inactive_days" class="block text-sm font-medium mb-1">Inactive Threshold (days)</label>
                            <input type="number" id="reg_inactive_days" name="inactive_days" min="1" value="30" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800" required>
                            <p class="text-xs text-gray-500 mt-1">After this many days of inactivity, your profile will show your posthumous letter.</p>
                        </div>
                        <div class="mb-4">
                            <label for="reg_posthumous_letter" class="block text-sm font-medium mb-1">Posthumous Letter (optional)</label>
                            <textarea id="reg_posthumous_letter" name="posthumous_letter" rows="3" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800"></textarea>
                            <p class="text-xs text-gray-500 mt-1">This message will be displayed if you're inactive beyond your threshold.</p>
                        </div>
                        <div class="mb-4">
                            <label class="block text-sm font-medium mb-2">Interests (select at least one)</label>
                            <div class="grid grid-cols-2 gap-2">
                                <?php foreach ($categories as $cat): ?>
                                    <label class="flex items-center space-x-2">
                                        <input type="checkbox" name="target_categories[]" value="<?= htmlspecialchars($cat) ?>" class="rounded text-primary focus:ring-primary">
                                        <span><?= ucfirst(htmlspecialchars($cat)) ?></span>
                                    </label>
                                <?php endforeach; ?>
                            </div>
                        </div>
                        <button type="submit" class="w-full px-4 py-2 bg-primary text-white rounded-md hover:bg-primary-dark transition">Register</button>
                    </form>
                </div>
            <?php endif; ?>
        </aside>
    </main>

    <!-- Footer -->
    <footer class="bg-dark dark:bg-darker text-gray-400 py-8">
        <div class="container mx-auto px-4">
            <div class="flex flex-col md:flex-row justify-between items-center">
                <div class="flex items-center space-x-2 mb-4 md:mb-0">
                    <i class="fas fa-rocket text-2xl"></i>
                    <span class="text-xl font-bold">MHCN+</span>
                </div>
                <div class="flex space-x-6">
                    <a href="#" class="hover:text-white transition">Terms</a>
                    <a href="#" class="hover:text-white transition">Privacy</a>
                    <a href="#" class="hover:text-white transition">Help</a>
                    <a href="#" class="hover:text-white transition">About</a>
                </div>
            </div>
            <div class="mt-6 text-center md:text-left">
                <p class="text-sm">© 2023 MHCN+. All rights reserved.</p>
            </div>
        </div>
    </footer>

    <!-- Modals -->
    <div id="formatting-modal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden">
        <div class="bg-white dark:bg-dark rounded-xl shadow-xl p-6 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div class="flex justify-between items-center mb-4">
                <h3 class="text-xl font-bold">Formatting Help</h3>
                <button onclick="document.getElementById('formatting-modal').classList.add('hidden')" class="text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="prose dark:prose-invert">
                <h4>Text Formatting</h4>
                <ul>
                    <li><strong>Bold:</strong> **text** or __text__</li>
                    <li><em>Italic:</em> *text* or _text_</li>
                    <li><del>Strikethrough:</del> ~~text~~</li>
                    <li><code>Inline code:</code> `code`</li>
                </ul>
                
                <h4>Links</h4>
                <p>[MHCN+](https://mhcn.plus)</p>
                
                <h4>Headings</h4>
                <pre># Heading 1
## Heading 2
### Heading 3</pre>
                
                <h4>Lists</h4>
                <pre>- Item 1
- Item 2
  - Subitem</pre>
                
                <pre>1. First item
2. Second item</pre>
                
                <h4>Code Blocks</h4>
                <pre>```python
print("Hello World")
```</pre>
                
                <h4>Blockquotes</h4>
                <pre>> This is a blockquote</pre>
                
                <h4>Horizontal Rule</h4>
                <pre>---</pre>
            </div>
        </div>
    </div>

    <!-- Post Modal (for expanded view) -->
    <div id="post-modal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden">
        <div class="bg-white dark:bg-dark rounded-xl shadow-xl p-6 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <!-- Content will be loaded via JS -->
        </div>
    </div>

    <script>
        // Formatting help modal
        document.getElementById('formatting-help').addEventListener('click', function() {
            document.getElementById('formatting-modal').classList.remove('hidden');
        });
        
        // Handle post interactions
        document.addEventListener('click', function(e) {
            // Like button
            if (e.target.classList.contains('like-btn') || e.target.closest('.like-btn')) {
                e.preventDefault();
                const btn = e.target.classList.contains('like-btn') ? e.target : e.target.closest('.like-btn');
                const postId = btn.dataset.postId;
                
                fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=like_post&post_id=${postId}`
                }).then(() => {
                    window.location.reload();
                });
            }
            
            // Report button
            if (e.target.classList.contains('report-btn') || e.target.closest('.report-btn')) {
                e.preventDefault();
                const btn = e.target.classList.contains('report-btn') ? e.target : e.target.closest('.report-btn');
                const postId = btn.dataset.postId;
                
                if (confirm('Are you sure you want to report this post?')) {
                    fetch('', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `action=report_post&post_id=${postId}`
                    }).then(() => {
                        window.location.reload();
                    });
                }
            }
            
            // View post (modal)
            if (e.target.classList.contains('view-post') || e.target.closest('.view-post')) {
                e.preventDefault();
                const postId = (e.target.classList.contains('view-post') ? 
                    e.target.dataset.postId : e.target.closest('.view-post').dataset.postId);
                
                // In a real app, you'd fetch the post details here
                // For this demo, we'll just show a placeholder
                document.getElementById('post-modal').classList.remove('hidden');
                document.getElementById('post-modal').querySelector('.modal-content').innerHTML = `
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-xl font-bold">Post Details</h3>
                        <button onclick="document.getElementById('post-modal').classList.add('hidden')" class="text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <p>Loading post ${postId}...</p>
                `;
            }
        });
        
        // Handle comment submission
        document.querySelectorAll('.comment-form').forEach(form => {
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                const postId = this.dataset.postId;
                const comment = this.querySelector('input[name="comment"]').value;
                
                fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=add_comment&post_id=${postId}&comment=${encodeURIComponent(comment)}`
                }).then(() => {
                    window.location.reload();
                });
            });
        });
        
        // Toggle comments
        document.querySelectorAll('.toggle-comments').forEach(btn => {
            btn.addEventListener('click', function() {
                const commentsSection = this.closest('.post-container').querySelector('.comments-section');
                commentsSection.classList.toggle('hidden');
                this.querySelector('span').textContent = commentsSection.classList.contains('hidden') ? 'Show' : 'Hide';
                this.querySelector('i').className = commentsSection.classList.contains('hidden') ? 
                    'fas fa-chevron-down ml-1' : 'fas fa-chevron-up ml-1';
            });
        });
        
        // Dark mode toggle (example - would need localStorage implementation)
        const darkModeToggle = document.createElement('button');
        darkModeToggle.className = 'fixed bottom-4 right-4 bg-primary text-white p-3 rounded-full shadow-lg z-40';
        darkModeToggle.innerHTML = '<i class="fas fa-moon"></i>';
        darkModeToggle.addEventListener('click', function() {
            document.documentElement.classList.toggle('dark');
            localStorage.setItem('darkMode', document.documentElement.classList.contains('dark'));
            this.innerHTML = document.documentElement.classList.contains('dark') ? 
                '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
        });
        
        // Initialize dark mode from localStorage
        if (localStorage.getItem('darkMode') === 'true') {
            document.documentElement.classList.add('dark');
            darkModeToggle.innerHTML = '<i class="fas fa-sun"></i>';
        }
        
        document.body.appendChild(darkModeToggle);

        // Dropdown do usuário (menu de perfil)
        const userMenuBtn = document.getElementById('user-menu-btn');
        const userMenu = document.getElementById('user-menu');
        if (userMenuBtn && userMenu) {
            document.addEventListener('click', function(e) {
                if (userMenuBtn.contains(e.target)) {
                    userMenu.classList.toggle('hidden');
                } else if (!userMenu.contains(e.target)) {
                    userMenu.classList.add('hidden');
                }
            });
        }
    </script>
</body>
</html>

<?php
// Post card template (included in the main file)
ob_start();
?>
<div class="post-container bg-white dark:bg-dark rounded-xl shadow-md overflow-hidden mb-6">
    <div class="p-6">
        <div class="flex items-start space-x-3">
            <a href="?profile=<?= urlencode($post['username']) ?>">
                <img src="https://ui-avatars.com/api/?name=<?= urlencode($post['username']) ?>&background=6d28d9&color=fff" 
                     alt="<?= htmlspecialchars($post['username']) ?>" class="w-10 h-10 rounded-full">
            </a>
            <div class="flex-1">
                <div class="flex items-center space-x-2">
                    <a href="?profile=<?= urlencode($post['username']) ?>" class="font-medium hover:underline"><?= htmlspecialchars($post['username']) ?></a>
                    <span class="text-xs text-gray-500">• <?= date('M j, Y g:i a', $post['timestamp']) ?></span>
                    <span class="px-2 py-1 text-xs bg-gray-100 dark:bg-gray-700 rounded-full"><?= ucfirst(htmlspecialchars($post['category'])) ?></span>
                </div>
                <a href="#" class="view-post block mt-1" data-post-id="<?= htmlspecialchars($post['id']) ?>">
                    <h3 class="text-lg font-semibold hover:text-primary transition"><?= htmlspecialchars($post['title']) ?></h3>
                </a>
            </div>
        </div>
        
        <div class="mt-4 post-content">
            <?= nl2br(htmlspecialchars($post['content'])) ?>
        </div>
        
        <?php if (!empty($post['image'])): ?>
            <div class="mt-4 rounded-lg overflow-hidden">
                <img src="plusfiles/<?= htmlspecialchars($post['image']) ?>" alt="Post image" class="w-full h-auto max-h-96 object-contain">
            </div>
        <?php endif; ?>
        
        <div class="mt-4 flex items-center justify-between border-t border-b border-gray-200 dark:border-gray-700 py-2">
            <button class="like-btn flex items-center space-x-1 text-gray-500 hover:text-primary transition" data-post-id="<?= htmlspecialchars($post['id']) ?>">
                <i class="fas fa-heart <?= (isset($currentUser) && in_array($currentUser['username'], $post['likes'] ?? [])) ? 'text-red-500' : '' ?>"></i>
                <span><?= count($post['likes'] ?? []) ?></span>
            </button>
            <button class="flex items-center space-x-1 text-gray-500 hover:text-primary transition toggle-comments">
                <i class="fas fa-comment"></i>
                <span><?= count($post['comments'] ?? []) ?></span>
                <span>Show</span>
                <i class="fas fa-chevron-down ml-1"></i>
            </button>
            <button class="report-btn flex items-center space-x-1 text-gray-500 hover:text-primary transition" data-post-id="<?= htmlspecialchars($post['id']) ?>">
                <i class="fas fa-flag"></i>
                <span>Report</span>
            </button>
        </div>
        
        <!-- Comments Section -->
        <div class="comments-section hidden mt-4">
            <?php if (isset($currentUser)): ?>
                <form class="comment-form mb-4 flex" data-post-id="<?= htmlspecialchars($post['id']) ?>">
                    <input type="text" name="comment" placeholder="Write a comment..." class="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-l-md focus:outline-none focus:ring-2 focus:ring-primary dark:bg-gray-800">
                    <button type="submit" class="px-4 py-2 bg-primary text-white rounded-r-md hover:bg-primary-dark transition">Post</button>
                </form>
            <?php endif; ?>
            
            <div class="space-y-4">
                <?php foreach ($post['comments'] ?? [] as $comment): ?>
                    <div class="flex space-x-3">
                        <img src="https://ui-avatars.com/api/?name=<?= urlencode($comment['username']) ?>&background=6d28d9&color=fff" 
                             alt="<?= htmlspecialchars($comment['username']) ?>" class="w-8 h-8 rounded-full">
                        <div>
                            <div class="bg-gray-100 dark:bg-gray-700 rounded-lg p-3">
                                <a href="?profile=<?= urlencode($comment['username']) ?>" class="font-medium hover:underline"><?= htmlspecialchars($comment['username']) ?></a>
                                <p class="mt-1"><?= htmlspecialchars($comment['text']) ?></p>
                            </div>
                            <div class="text-xs text-gray-500 mt-1"><?= date('M j, g:i a', $comment['timestamp']) ?></div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
</div>
<?php
$post_card = ob_get_clean();
file_put_contents('post_card.php', $post_card);
?>
