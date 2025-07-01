<?php
// Start session
session_start();

// Configuration
define('MAX_POST_LENGTH', 450);
define('MAX_IMAGE_SIZE', 1048576); // 1MB in bytes
define('POST_LIFETIME', 7 * 24 * 60 * 60); // 7 days in seconds
define('REPORT_THRESHOLD', 5);
define('AES_KEY', 'MHCN+_AES256_KEY_123!'); // In production, use a more secure key management
define('AES_IV', 'MHCN+_INIT_VECTOR_!'); // Should be 16 bytes for AES-256-CBC

// Categories
$categories = [
    'games' => 'Games',
    'science' => 'Science',
    'sports' => 'Sports',
    'news' => 'News',
    'lifestyle' => 'Lifestyle',
    'programming' => 'Programming'
];

// Blacklist of offensive words (simplified)
$blacklist = ['badword1', 'badword2', 'offensive', 'hate', 'racist'];

// Data directories
if (!file_exists('plususers')) mkdir('plususers');
if (!file_exists('plusfiles')) mkdir('plusfiles');
if (!file_exists('reported_posts.json')) file_put_contents('reported_posts.json', json_encode([]));

// Helper functions
function encryptData($data) {
    $encrypted = openssl_encrypt(json_encode($data), 'AES-256-CBC', AES_KEY, 0, AES_IV);
    return base64_encode($encrypted);
}

function decryptData($encrypted) {
    $decoded = base64_decode($encrypted);
    $decrypted = openssl_decrypt($decoded, 'AES-256-CBC', AES_KEY, 0, AES_IV);
    return json_decode($decrypted, true);
}

function sanitizeInput($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

function compressImage($source, $destination, $quality) {
    $info = getimagesize($source);
    
    if ($info['mime'] == 'image/jpeg') {
        $image = imagecreatefromjpeg($source);
        imagejpeg($image, $destination, $quality);
    } elseif ($info['mime'] == 'image/png') {
        $image = imagecreatefrompng($source);
        imagepng($image, $destination, 9); // PNG quality is 0-9
    } elseif ($info['mime'] == 'image/gif') {
        $image = imagecreatefromgif($source);
        imagegif($image, $destination);
    }
    
    return $destination;
}

function isUserInactive($userData) {
    if (!isset($userData['last_active']) || !isset($userData['inactive_days'])) {
        return false;
    }
    
    $inactiveSeconds = $userData['inactive_days'] * 24 * 60 * 60;
    $currentTime = time();
    $lastActive = strtotime($userData['last_active']);
    
    return ($currentTime - $lastActive) > $inactiveSeconds;
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'register':
                // Sanitize inputs
                $username = sanitizeInput($_POST['username']);
                $email = filter_var(sanitizeInput($_POST['email']), FILTER_SANITIZE_EMAIL);
                $password = password_hash(sanitizeInput($_POST['password']), PASSWORD_DEFAULT);
                $birthdate = sanitizeInput($_POST['birthdate']);
                $bio = sanitizeInput($_POST['bio']);
                $inactiveDays = intval($_POST['inactive_days']);
                $posthumousLetter = sanitizeInput($_POST['posthumous_letter']);
                $targetCategories = array_intersect(array_keys($categories), $_POST['categories'] ?? []);
                
                // Validate
                if (empty($username) || empty($email) || empty($password) || empty($birthdate)) {
                    $_SESSION['error'] = 'Please fill all required fields.';
                    break;
                }
                
                // Check if username or email exists
                $userFiles = glob('plususers/*.json');
                foreach ($userFiles as $file) {
                    $userData = decryptData(file_get_contents($file));
                    if ($userData['username'] === $username) {
                        $_SESSION['error'] = 'Username already taken.';
                        break 2;
                    }
                    if ($userData['email'] === $email) {
                        $_SESSION['error'] = 'Email already registered.';
                        break 2;
                    }
                }
                
                // Create user data
                $userData = [
                    'username' => $username,
                    'email' => $email,
                    'password' => $password,
                    'birthdate' => $birthdate,
                    'bio' => $bio,
                    'inactive_days' => $inactiveDays,
                    'posthumous_letter' => $posthumousLetter,
                    'target_categories' => $targetCategories,
                    'created_at' => date('Y-m-d H:i:s'),
                    'last_active' => date('Y-m-d H:i:s'),
                    'avatar' => null
                ];
                
                // Save user
                $filename = 'plususers/' . uniqid('user_', true) . '.json';
                file_put_contents($filename, encryptData($userData));
                
                // Log in the user
                $_SESSION['user'] = $userData;
                $_SESSION['user_file'] = $filename;
                $_SESSION['success'] = 'Registration successful! Welcome to MHCN+.';
                break;
                
            case 'login':
                $username = sanitizeInput($_POST['username']);
                $password = sanitizeInput($_POST['password']);
                
                $userFiles = glob('plususers/*.json');
                foreach ($userFiles as $file) {
                    $userData = decryptData(file_get_contents($file));
                    if ($userData['username'] === $username && password_verify($password, $userData['password'])) {
                        // Update last active time
                        $userData['last_active'] = date('Y-m-d H:i:s');
                        file_put_contents($file, encryptData($userData));
                        
                        $_SESSION['user'] = $userData;
                        $_SESSION['user_file'] = $file;
                        $_SESSION['success'] = 'Login successful! Welcome back.';
                        break 2;
                    }
                }
                
                $_SESSION['error'] = 'Invalid username or password.';
                break;
                
            case 'create_post':
                if (!isset($_SESSION['user'])) {
                    $_SESSION['error'] = 'You must be logged in to post.';
                    break;
                }
                
                $title = sanitizeInput($_POST['title']);
                $content = sanitizeInput($_POST['content']);
                $category = sanitizeInput($_POST['category']);
                
                // Validate
                if (empty($title) || empty($content) || empty($category) || !array_key_exists($category, $categories)) {
                    $_SESSION['error'] = 'Please fill all required fields and select a valid category.';
                    break;
                }
                
                // Check for blacklisted words
                foreach ($blacklist as $word) {
                    if (stripos($title, $word) !== false || stripos($content, $word) !== false) {
                        $_SESSION['error'] = 'Your post contains inappropriate content.';
                        break 2;
                    }
                }
                
                // Handle image upload
                $imagePath = null;
                if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
                    $fileInfo = $_FILES['image'];
                    $fileType = strtolower(pathinfo($fileInfo['name'], PATHINFO_EXTENSION));
                    
                    // Check if file is an image or GIF
                    $allowedTypes = ['jpg', 'jpeg', 'png', 'gif'];
                    if (!in_array($fileType, $allowedTypes)) {
                        $_SESSION['error'] = 'Only JPG, PNG, and GIF files are allowed.';
                        break;
                    }
                    
                    // Check file size
                    if ($fileInfo['size'] > MAX_IMAGE_SIZE) {
                        // Try to compress
                        $tempPath = $fileInfo['tmp_name'];
                        $newPath = 'plusfiles/' . uniqid('img_', true) . '.' . $fileType;
                        
                        if ($fileType === 'gif') {
                            // For GIFs, we can't compress easily, so just reject if too large
                            $_SESSION['error'] = 'GIF file is too large (max 1MB).';
                            break;
                        } else {
                            // Compress image
                            $quality = 75; // Start with 75% quality
                            compressImage($tempPath, $newPath, $quality);
                            
                            // Check if compressed size is acceptable
                            if (filesize($newPath) > MAX_IMAGE_SIZE) {
                                unlink($newPath);
                                $_SESSION['error'] = 'Image is too large even after compression.';
                                break;
                            }
                            
                            $imagePath = $newPath;
                        }
                    } else {
                        // File size is acceptable, move it
                        $newPath = 'plusfiles/' . uniqid('img_', true) . '.' . $fileType;
                        move_uploaded_file($fileInfo['tmp_name'], $newPath);
                        $imagePath = $newPath;
                    }
                }
                
                // Create post data
                $postId = uniqid('post_', true);
                $postData = [
                    'id' => $postId,
                    'user_id' => $_SESSION['user_file'],
                    'username' => $_SESSION['user']['username'],
                    'title' => $title,
                    'content' => $content,
                    'category' => $category,
                    'image' => $imagePath,
                    'created_at' => date('Y-m-d H:i:s'),
                    'likes' => [],
                    'reports' => [],
                    'likes_count' => 0,
                    'reports_count' => 0
                ];
                
                // Load existing posts
                $posts = [];
                if (file_exists('posts.json')) {
                    $posts = decryptData(file_get_contents('posts.json'));
                }
                
                // Add new post
                $posts[$postId] = $postData;
                file_put_contents('posts.json', encryptData($posts));
                
                $_SESSION['success'] = 'Post created successfully!';
                break;
                
            case 'like_post':
                if (!isset($_SESSION['user'])) {
                    echo json_encode(['success' => false, 'message' => 'Not logged in']);
                    exit;
                }
                
                $postId = sanitizeInput($_POST['post_id']);
                $userId = $_SESSION['user_file'];
                
                if (!file_exists('posts.json')) {
                    echo json_encode(['success' => false, 'message' => 'No posts found']);
                    exit;
                }
                
                $posts = decryptData(file_get_contents('posts.json'));
                if (!isset($posts[$postId])) {
                    echo json_encode(['success' => false, 'message' => 'Post not found']);
                    exit;
                }
                
                // Toggle like
                $post = $posts[$postId];
                $liked = in_array($userId, $post['likes']);
                
                if ($liked) {
                    // Remove like
                    $post['likes'] = array_diff($post['likes'], [$userId]);
                    $post['likes_count']--;
                } else {
                    // Add like
                    $post['likes'][] = $userId;
                    $post['likes_count']++;
                }
                
                $posts[$postId] = $post;
                file_put_contents('posts.json', encryptData($posts));
                
                echo json_encode(['success' => true, 'liked' => !$liked, 'likes_count' => $post['likes_count']]);
                exit;
                
            case 'report_post':
                if (!isset($_SESSION['user'])) {
                    echo json_encode(['success' => false, 'message' => 'Not logged in']);
                    exit;
                }
                
                $postId = sanitizeInput($_POST['post_id']);
                $userId = $_SESSION['user_file'];
                
                if (!file_exists('posts.json')) {
                    echo json_encode(['success' => false, 'message' => 'No posts found']);
                    exit;
                }
                
                $posts = decryptData(file_get_contents('posts.json'));
                if (!isset($posts[$postId])) {
                    echo json_encode(['success' => false, 'message' => 'Post not found']);
                    exit;
                }
                
                // Check if already reported
                $post = $posts[$postId];
                if (in_array($userId, $post['reports'])) {
                    echo json_encode(['success' => false, 'message' => 'Already reported']);
                    exit;
                }
                
                // Add report
                $post['reports'][] = $userId;
                $post['reports_count']++;
                $posts[$postId] = $post;
                
                // Check if reached threshold
                if ($post['reports_count'] >= REPORT_THRESHOLD) {
                    $reportedPosts = [];
                    if (file_exists('reported_posts.json')) {
                        $reportedPosts = json_decode(file_get_contents('reported_posts.json'), true);
                    }
                    
                    $reportedPosts[$postId] = $post;
                    file_put_contents('reported_posts.json', json_encode($reportedPosts));
                }
                
                file_put_contents('posts.json', encryptData($posts));
                
                echo json_encode(['success' => true, 'reports_count' => $post['reports_count']]);
                exit;
                
            case 'update_profile':
                if (!isset($_SESSION['user'])) {
                    $_SESSION['error'] = 'You must be logged in to update your profile.';
                    break;
                }
                
                $bio = sanitizeInput($_POST['bio']);
                $inactiveDays = intval($_POST['inactive_days']);
                $posthumousLetter = sanitizeInput($_POST['posthumous_letter']);
                $targetCategories = array_intersect(array_keys($categories), $_POST['categories'] ?? []);
                
                // Update user data
                $userData = $_SESSION['user'];
                $userData['bio'] = $bio;
                $userData['inactive_days'] = $inactiveDays;
                $userData['posthumous_letter'] = $posthumousLetter;
                $userData['target_categories'] = $targetCategories;
                $userData['last_active'] = date('Y-m-d H:i:s');
                
                // Handle avatar upload
                if (isset($_FILES['avatar']) && $_FILES['avatar']['error'] === UPLOAD_ERR_OK) {
                    $fileInfo = $_FILES['avatar'];
                    $fileType = strtolower(pathinfo($fileInfo['name'], PATHINFO_EXTENSION));
                    
                    // Check if file is an image
                    $allowedTypes = ['jpg', 'jpeg', 'png'];
                    if (!in_array($fileType, $allowedTypes)) {
                        $_SESSION['error'] = 'Only JPG and PNG files are allowed for avatars.';
                        break;
                    }
                    
                    // Check file size
                    if ($fileInfo['size'] > MAX_IMAGE_SIZE) {
                        // Try to compress
                        $tempPath = $fileInfo['tmp_name'];
                        $newPath = 'plusfiles/' . uniqid('avatar_', true) . '.' . $fileType;
                        
                        $quality = 75; // Start with 75% quality
                        compressImage($tempPath, $newPath, $quality);
                        
                        // Check if compressed size is acceptable
                        if (filesize($newPath) > MAX_IMAGE_SIZE) {
                            unlink($newPath);
                            $_SESSION['error'] = 'Avatar is too large even after compression.';
                            break;
                        }
                        
                        // Delete old avatar if exists
                        if ($userData['avatar'] && file_exists($userData['avatar'])) {
                            unlink($userData['avatar']);
                        }
                        
                        $userData['avatar'] = $newPath;
                    } else {
                        // File size is acceptable, move it
                        $newPath = 'plusfiles/' . uniqid('avatar_', true) . '.' . $fileType;
                        move_uploaded_file($fileInfo['tmp_name'], $newPath);
                        
                        // Delete old avatar if exists
                        if ($userData['avatar'] && file_exists($userData['avatar'])) {
                            unlink($userData['avatar']);
                        }
                        
                        $userData['avatar'] = $newPath;
                    }
                }
                
                // Save updated user data
                $_SESSION['user'] = $userData;
                file_put_contents($_SESSION['user_file'], encryptData($userData));
                
                $_SESSION['success'] = 'Profile updated successfully!';
                break;
        }
    }
}

// Clean up old posts
if (file_exists('posts.json')) {
    $posts = decryptData(file_get_contents('posts.json'));
    $now = time();
    $changed = false;
    
    foreach ($posts as $postId => $post) {
        $postTime = strtotime($post['created_at']);
        if (($now - $postTime) > POST_LIFETIME) {
            // Delete associated image
            if ($post['image'] && file_exists($post['image'])) {
                unlink($post['image']);
            }
            
            // Remove post
            unset($posts[$postId]);
            $changed = true;
        }
    }
    
    if ($changed) {
        file_put_contents('posts.json', encryptData($posts));
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

// Get current user profile if viewing another profile
$viewingUser = null;
if (isset($_GET['profile']) && $_GET['profile'] !== ($_SESSION['user']['username'] ?? '')) {
    $username = sanitizeInput($_GET['profile']);
    $userFiles = glob('plususers/*.json');
    
    foreach ($userFiles as $file) {
        $userData = decryptData(file_get_contents($file));
        if ($userData['username'] === $username) {
            $viewingUser = $userData;
            $viewingUserFile = $file;
            break;
        }
    }
}

// Get posts for feed
$feedPosts = [];
if (file_exists('posts.json')) {
    $allPosts = decryptData(file_get_contents('posts.json'));
    
    // Sort by relevance (category match + likes + recency)
    usort($allPosts, function($a, $b) {
        $aScore = 0;
        $bScore = 0;
        
        // Category match (if logged in)
        if (isset($_SESSION['user'])) {
            if (in_array($a['category'], $_SESSION['user']['target_categories'])) {
                $aScore += 50;
            }
            if (in_array($b['category'], $_SESSION['user']['target_categories'])) {
                $bScore += 50;
            }
        }
        
        // Likes
        $aScore += $a['likes_count'] * 10;
        $bScore += $b['likes_count'] * 10;
        
        // Recency (newer posts get higher score)
        $aTime = strtotime($a['created_at']);
        $bTime = strtotime($b['created_at']);
        $aScore += ($aTime / 10000); // Scale down to reasonable numbers
        $bScore += ($bTime / 10000);
        
        return $bScore - $aScore;
    });
    
    $feedPosts = $allPosts;
}

// Search functionality
$searchResults = [];
if (isset($_GET['search'])) {
    $searchTerm = sanitizeInput($_GET['search']);
    
    if (!empty($searchTerm)) {
        // Search users
        $userFiles = glob('plususers/*.json');
        foreach ($userFiles as $file) {
            $userData = decryptData(file_get_contents($file));
            if (stripos($userData['username'], $searchTerm) !== false) {
                $searchResults['users'][] = $userData;
            }
        }
        
        // Search posts
        if (file_exists('posts.json')) {
            $allPosts = decryptData(file_get_contents('posts.json'));
            foreach ($allPosts as $post) {
                if (stripos($post['title'], $searchTerm) !== false || 
                    stripos($post['content'], $searchTerm) !== false) {
                    $searchResults['posts'][] = $post;
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MHCN+ - Modern Hybrid Social Network</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        :root {
            --primary: #6d28d9;
            --primary-dark: #5b21b6;
            --secondary: #f59e0b;
            --dark: #1e293b;
            --light: #f8fafc;
        }
        
        body {
            background-color: #0f172a;
            color: #f8fafc;
            font-family: 'Inter', sans-serif;
        }
        
        .gradient-bg {
            background: linear-gradient(135deg, #6d28d9 0%, #f59e0b 100%);
        }
        
        .post-card {
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
        }
        
        .post-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
        }
        
        .like-btn.liked {
            color: #ef4444;
        }
        
        .report-btn.reported {
            color: #f59e0b;
        }
        
        .avatar {
            transition: all 0.3s ease;
        }
        
        .avatar:hover {
            transform: scale(1.1);
        }
        
        @keyframes pulse {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.5;
            }
        }
        
        .animate-pulse {
            animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }
    </style>
</head>
<body class="min-h-screen">
    <!-- Header -->
    <header class="gradient-bg text-white shadow-lg">
        <div class="container mx-auto px-4 py-4 flex justify-between items-center">
            <div class="flex items-center space-x-2">
                <i class="fas fa-rocket text-2xl"></i>
                <h1 class="text-2xl font-bold">MHCN+</h1>
            </div>
            
            <div class="flex items-center space-x-4">
                <?php if (isset($_SESSION['user'])): ?>
                    <div class="relative group">
                        <button class="flex items-center space-x-2 focus:outline-none">
                            <span class="font-medium"><?= htmlspecialchars($_SESSION['user']['username']) ?></span>
                            <?php if ($_SESSION['user']['avatar']): ?>
                                <img src="<?= htmlspecialchars($_SESSION['user']['avatar']) ?>" alt="Avatar" class="w-8 h-8 rounded-full object-cover avatar">
                            <?php else: ?>
                                <div class="w-8 h-8 rounded-full bg-purple-600 flex items-center justify-center">
                                    <i class="fas fa-user text-white"></i>
                                </div>
                            <?php endif; ?>
                        </button>
                        <div class="absolute right-0 mt-2 w-48 bg-slate-800 rounded-md shadow-lg py-1 z-50 hidden group-hover:block">
                            <a href="?profile=<?= htmlspecialchars($_SESSION['user']['username']) ?>" class="block px-4 py-2 text-sm hover:bg-slate-700">Profile</a>
                            <a href="#" onclick="document.getElementById('settings-modal').classList.remove('hidden')" class="block px-4 py-2 text-sm hover:bg-slate-700">Settings</a>
                            <a href="?logout" class="block px-4 py-2 text-sm hover:bg-slate-700">Logout</a>
                        </div>
                    </div>
                <?php else: ?>
                    <button onclick="document.getElementById('login-modal').classList.remove('hidden')" class="px-4 py-2 rounded-md bg-white text-purple-700 font-medium hover:bg-opacity-90 transition">Login</button>
                <?php endif; ?>
            </div>
        </div>
    </header>
    
    <!-- Main Content -->
    <main class="container mx-auto px-4 py-8">
        <?php if (isset($_SESSION['error'])): ?>
            <div class="bg-red-600 text-white px-4 py-3 rounded-md mb-6 flex justify-between items-center">
                <span><?= htmlspecialchars($_SESSION['error']) ?></span>
                <button onclick="this.parentElement.remove()" class="text-white hover:text-gray-200">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>
        
        <?php if (isset($_SESSION['success'])): ?>
            <div class="bg-green-600 text-white px-4 py-3 rounded-md mb-6 flex justify-between items-center">
                <span><?= htmlspecialchars($_SESSION['success']) ?></span>
                <button onclick="this.parentElement.remove()" class="text-white hover:text-gray-200">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <?php unset($_SESSION['success']); ?>
        <?php endif; ?>
        
        <!-- Search Bar -->
        <div class="mb-8">
            <form action="" method="GET" class="flex">
                <input type="text" name="search" placeholder="Search users or posts..." class="flex-grow px-4 py-3 rounded-l-md bg-slate-700 text-white focus:outline-none focus:ring-2 focus:ring-purple-500">
                <button type="submit" class="px-6 py-3 bg-purple-600 text-white rounded-r-md hover:bg-purple-700 transition">
                    <i class="fas fa-search"></i>
                </button>
            </form>
        </div>
        
        <?php if (isset($_GET['search']) && !empty($searchTerm)): ?>
            <!-- Search Results -->
            <div class="mb-8">
                <h2 class="text-2xl font-bold mb-4">Search Results for "<?= htmlspecialchars($searchTerm) ?>"</h2>
                
                <?php if (empty($searchResults)): ?>
                    <p class="text-slate-400">No results found.</p>
                <?php else: ?>
                    <?php if (!empty($searchResults['users'])): ?>
                        <div class="mb-8">
                            <h3 class="text-xl font-semibold mb-3">Users</h3>
                            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                                <?php foreach ($searchResults['users'] as $user): ?>
                                    <a href="?profile=<?= htmlspecialchars($user['username']) ?>" class="bg-slate-800 rounded-lg p-4 flex items-center space-x-3 hover:bg-slate-700 transition">
                                        <?php if ($user['avatar']): ?>
                                            <img src="<?= htmlspecialchars($user['avatar']) ?>" alt="Avatar" class="w-12 h-12 rounded-full object-cover">
                                        <?php else: ?>
                                            <div class="w-12 h-12 rounded-full bg-purple-600 flex items-center justify-center">
                                                <i class="fas fa-user text-white"></i>
                                            </div>
                                        <?php endif; ?>
                                        <div>
                                            <h4 class="font-medium"><?= htmlspecialchars($user['username']) ?></h4>
                                            <p class="text-slate-400 text-sm truncate"><?= htmlspecialchars($user['bio']) ?></p>
                                        </div>
                                    </a>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    <?php endif; ?>
                    
                    <?php if (!empty($searchResults['posts'])): ?>
                        <div>
                            <h3 class="text-xl font-semibold mb-3">Posts</h3>
                            <div class="grid grid-cols-1 gap-6">
                                <?php foreach ($searchResults['posts'] as $post): ?>
                                    <div class="post-card rounded-lg overflow-hidden">
                                        <div class="p-6">
                                            <div class="flex items-center justify-between mb-3">
                                                <div class="flex items-center space-x-3">
                                                    <a href="?profile=<?= htmlspecialchars($post['username']) ?>" class="flex items-center space-x-2">
                                                        <span class="font-medium"><?= htmlspecialchars($post['username']) ?></span>
                                                    </a>
                                                    <span class="text-slate-400 text-sm"><?= date('M j, Y', strtotime($post['created_at'])) ?></span>
                                                </div>
                                                <span class="px-3 py-1 bg-slate-700 rounded-full text-xs font-medium"><?= htmlspecialchars($categories[$post['category']] ?? 'Unknown') ?></span>
                                            </div>
                                            
                                            <h3 class="text-xl font-bold mb-2"><?= htmlspecialchars($post['title']) ?></h3>
                                            <p class="text-slate-300 mb-4"><?= nl2br(htmlspecialchars($post['content'])) ?></p>
                                            
                                            <?php if ($post['image']): ?>
                                                <div class="mb-4 rounded-lg overflow-hidden">
                                                    <img src="<?= htmlspecialchars($post['image']) ?>" alt="Post image" class="w-full h-auto max-h-96 object-contain rounded-lg">
                                                </div>
                                            <?php endif; ?>
                                            
                                            <div class="flex items-center justify-between pt-3 border-t border-slate-700">
                                                <div class="flex items-center space-x-4">
                                                    <button onclick="likePost('<?= htmlspecialchars($post['id']) ?>')" class="like-btn flex items-center space-x-1 <?= isset($_SESSION['user']) && in_array($_SESSION['user_file'], $post['likes']) ? 'liked' : '' ?>">
                                                        <i class="fas fa-heart"></i>
                                                        <span><?= $post['likes_count'] ?></span>
                                                    </button>
                                                </div>
                                                <button onclick="reportPost('<?= htmlspecialchars($post['id']) ?>')" class="report-btn text-slate-400 hover:text-yellow-500 <?= isset($_SESSION['user']) && in_array($_SESSION['user_file'], $post['reports']) ? 'reported' : '' ?>">
                                                    <i class="fas fa-flag"></i>
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        <?php elseif (isset($_GET['profile'])): ?>
            <!-- Profile Page -->
            <?php if ($viewingUser): ?>
                <div class="mb-8">
                    <div class="flex flex-col md:flex-row items-start md:items-center justify-between mb-8">
                        <div class="flex items-center space-x-6 mb-4 md:mb-0">
                            <?php if ($viewingUser['avatar']): ?>
                                <img src="<?= htmlspecialchars($viewingUser['avatar']) ?>" alt="Avatar" class="w-20 h-20 rounded-full object-cover border-4 border-purple-500 avatar">
                            <?php else: ?>
                                <div class="w-20 h-20 rounded-full bg-purple-600 flex items-center justify-center border-4 border-purple-500">
                                    <i class="fas fa-user text-white text-3xl"></i>
                                </div>
                            <?php endif; ?>
                            
                            <div>
                                <h2 class="text-2xl font-bold"><?= htmlspecialchars($viewingUser['username']) ?></h2>
                                <p class="text-slate-400">Joined <?= date('M Y', strtotime($viewingUser['created_at'])) ?></p>
                            </div>
                        </div>
                        
                        <?php if ($viewingUserFile === ($_SESSION['user_file'] ?? '')): ?>
                            <button onclick="document.getElementById('profile-modal').classList.remove('hidden')" class="px-4 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition">
                                Edit Profile
                            </button>
                        <?php endif; ?>
                    </div>
                    
                    <?php if (isUserInactive($viewingUser)): ?>
                        <!-- Posthumous Letter -->
                        <div class="bg-slate-800 rounded-lg p-6 mb-8 border-l-4 border-purple-500">
                            <h3 class="text-xl font-bold mb-4 text-purple-400">Posthumous Letter</h3>
                            <p class="text-slate-300 whitespace-pre-line"><?= nl2br(htmlspecialchars($viewingUser['posthumous_letter'])) ?></p>
                        </div>
                    <?php else: ?>
                        <!-- Bio -->
                        <div class="bg-slate-800 rounded-lg p-6 mb-8">
                            <h3 class="text-xl font-bold mb-4">Bio</h3>
                            <p class="text-slate-300 whitespace-pre-line"><?= nl2br(htmlspecialchars($viewingUser['bio'])) ?></p>
                            
                            <?php if (!empty($viewingUser['target_categories'])): ?>
                                <div class="mt-4">
                                    <h4 class="font-medium mb-2">Interests</h4>
                                    <div class="flex flex-wrap gap-2">
                                        <?php foreach ($viewingUser['target_categories'] as $cat): ?>
                                            <span class="px-3 py-1 bg-slate-700 rounded-full text-xs font-medium"><?= htmlspecialchars($categories[$cat] ?? $cat) ?></span>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                            <?php endif; ?>
                        </div>
                        
                        <!-- User Posts -->
                        <h3 class="text-xl font-bold mb-4">Posts</h3>
                        <?php
                            $userPosts = array_filter($feedPosts, function($post) use ($viewingUserFile) {
                                return $post['user_id'] === $viewingUserFile;
                            });
                        ?>
                        
                        <?php if (empty($userPosts)): ?>
                            <p class="text-slate-400">No posts yet.</p>
                        <?php else: ?>
                            <div class="grid grid-cols-1 gap-6">
                                <?php foreach ($userPosts as $post): ?>
                                    <div class="post-card rounded-lg overflow-hidden">
                                        <div class="p-6">
                                            <div class="flex items-center justify-between mb-3">
                                                <div class="flex items-center space-x-3">
                                                    <span class="text-slate-400 text-sm"><?= date('M j, Y', strtotime($post['created_at'])) ?></span>
                                                </div>
                                                <span class="px-3 py-1 bg-slate-700 rounded-full text-xs font-medium"><?= htmlspecialchars($categories[$post['category']] ?? 'Unknown') ?></span>
                                            </div>
                                            
                                            <h3 class="text-xl font-bold mb-2"><?= htmlspecialchars($post['title']) ?></h3>
                                            <p class="text-slate-300 mb-4"><?= nl2br(htmlspecialchars($post['content'])) ?></p>
                                            
                                            <?php if ($post['image']): ?>
                                                <div class="mb-4 rounded-lg overflow-hidden">
                                                    <img src="<?= htmlspecialchars($post['image']) ?>" alt="Post image" class="w-full h-auto max-h-96 object-contain rounded-lg">
                                                </div>
                                            <?php endif; ?>
                                            
                                            <div class="flex items-center justify-between pt-3 border-t border-slate-700">
                                                <div class="flex items-center space-x-4">
                                                    <button onclick="likePost('<?= htmlspecialchars($post['id']) ?>')" class="like-btn flex items-center space-x-1 <?= isset($_SESSION['user']) && in_array($_SESSION['user_file'], $post['likes']) ? 'liked' : '' ?>">
                                                        <i class="fas fa-heart"></i>
                                                        <span><?= $post['likes_count'] ?></span>
                                                    </button>
                                                </div>
                                                <button onclick="reportPost('<?= htmlspecialchars($post['id']) ?>')" class="report-btn text-slate-400 hover:text-yellow-500 <?= isset($_SESSION['user']) && in_array($_SESSION['user_file'], $post['reports']) ? 'reported' : '' ?>">
                                                    <i class="fas fa-flag"></i>
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            <?php else: ?>
                <div class="text-center py-12">
                    <h2 class="text-2xl font-bold mb-4">User not found</h2>
                    <p class="text-slate-400 mb-6">The user you're looking for doesn't exist or may have been deleted.</p>
                    <a href="index.php" class="px-6 py-3 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition">Go to Home</a>
                </div>
            <?php endif; ?>
        <?php else: ?>
            <!-- Main Feed -->
            <div class="flex flex-col lg:flex-row gap-8">
                <!-- Left Sidebar (Categories) -->
                <div class="lg:w-1/4">
                    <div class="bg-slate-800 rounded-lg p-6 sticky top-4">
                        <h3 class="text-xl font-bold mb-4">Categories</h3>
                        <ul class="space-y-2">
                            <li><a href="?" class="block px-3 py-2 rounded-md hover:bg-slate-700 transition">All Posts</a></li>
                            <?php foreach ($categories as $key => $name): ?>
                                <li><a href="?category=<?= htmlspecialchars($key) ?>" class="block px-3 py-2 rounded-md hover:bg-slate-700 transition"><?= htmlspecialchars($name) ?></a></li>
                            <?php endforeach; ?>
                        </ul>
                        
                        <?php if (isset($_SESSION['user'])): ?>
                            <div class="mt-8">
                                <button onclick="document.getElementById('create-post-modal').classList.remove('hidden')" class="w-full px-4 py-3 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition flex items-center justify-center space-x-2">
                                    <i class="fas fa-plus"></i>
                                    <span>Create Post</span>
                                </button>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                
                <!-- Feed Content -->
                <div class="lg:w-3/4">
                    <?php if (empty($feedPosts)): ?>
                        <div class="text-center py-12">
                            <h2 class="text-2xl font-bold mb-4">No posts yet</h2>
                            <p class="text-slate-400 mb-6">Be the first to create a post!</p>
                            <?php if (isset($_SESSION['user'])): ?>
                                <button onclick="document.getElementById('create-post-modal').classList.remove('hidden')" class="px-6 py-3 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition">
                                    Create Post
                                </button>
                            <?php else: ?>
                                <button onclick="document.getElementById('login-modal').classList.remove('hidden')" class="px-6 py-3 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition">
                                    Login to Post
                                </button>
                            <?php endif; ?>
                        </div>
                    <?php else: ?>
                        <div class="grid grid-cols-1 gap-6">
                            <?php foreach ($feedPosts as $post): ?>
                                <div class="post-card rounded-lg overflow-hidden">
                                    <div class="p-6">
                                        <div class="flex items-center justify-between mb-3">
                                            <div class="flex items-center space-x-3">
                                                <a href="?profile=<?= htmlspecialchars($post['username']) ?>" class="flex items-center space-x-2">
                                                    <span class="font-medium"><?= htmlspecialchars($post['username']) ?></span>
                                                </a>
                                                <span class="text-slate-400 text-sm"><?= date('M j, Y', strtotime($post['created_at'])) ?></span>
                                            </div>
                                            <span class="px-3 py-1 bg-slate-700 rounded-full text-xs font-medium"><?= htmlspecialchars($categories[$post['category']] ?? 'Unknown') ?></span>
                                        </div>
                                        
                                        <h3 class="text-xl font-bold mb-2"><?= htmlspecialchars($post['title']) ?></h3>
                                        <p class="text-slate-300 mb-4"><?= nl2br(htmlspecialchars($post['content'])) ?></p>
                                        
                                        <?php if ($post['image']): ?>
                                            <div class="mb-4 rounded-lg overflow-hidden">
                                                <img src="<?= htmlspecialchars($post['image']) ?>" alt="Post image" class="w-full h-auto max-h-96 object-contain rounded-lg">
                                            </div>
                                        <?php endif; ?>
                                        
                                        <div class="flex items-center justify-between pt-3 border-t border-slate-700">
                                            <div class="flex items-center space-x-4">
                                                <button onclick="likePost('<?= htmlspecialchars($post['id']) ?>')" class="like-btn flex items-center space-x-1 <?= isset($_SESSION['user']) && in_array($_SESSION['user_file'], $post['likes']) ? 'liked' : '' ?>">
                                                    <i class="fas fa-heart"></i>
                                                    <span><?= $post['likes_count'] ?></span>
                                                </button>
                                            </div>
                                            <button onclick="reportPost('<?= htmlspecialchars($post['id']) ?>')" class="report-btn text-slate-400 hover:text-yellow-500 <?= isset($_SESSION['user']) && in_array($_SESSION['user_file'], $post['reports']) ? 'reported' : '' ?>">
                                                <i class="fas fa-flag"></i>
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>
    </main>
    
    <!-- Modals -->
    
    <!-- Login Modal -->
    <div id="login-modal" class="fixed inset-0 bg-black bg-opacity-50 z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 rounded-lg shadow-xl w-full max-w-md">
            <div class="p-6">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="text-xl font-bold">Login to MHCN+</h3>
                    <button onclick="document.getElementById('login-modal').classList.add('hidden')" class="text-slate-400 hover:text-white">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                
                <form action="" method="POST">
                    <input type="hidden" name="action" value="login">
                    
                    <div class="mb-4">
                        <label for="login-username" class="block text-sm font-medium mb-2">Username</label>
                        <input type="text" id="login-username" name="username" required class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500">
                    </div>
                    
                    <div class="mb-6">
                        <label for="login-password" class="block text-sm font-medium mb-2">Password</label>
                        <input type="password" id="login-password" name="password" required class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500">
                    </div>
                    
                    <div class="flex items-center justify-between">
                        <button type="submit" class="px-4 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition">Login</button>
                        <button type="button" onclick="document.getElementById('login-modal').classList.add('hidden'); document.getElementById('register-modal').classList.remove('hidden')" class="text-purple-400 hover:text-purple-300 text-sm">
                            Don't have an account? Register
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Register Modal -->
    <div id="register-modal" class="fixed inset-0 bg-black bg-opacity-50 z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 rounded-lg shadow-xl w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div class="p-6">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="text-xl font-bold">Join MHCN+</h3>
                    <button onclick="document.getElementById('register-modal').classList.add('hidden')" class="text-slate-400 hover:text-white">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                
                <form action="" method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="action" value="register">
                    
                    <div class="mb-4">
                        <label for="register-username" class="block text-sm font-medium mb-2">Username</label>
                        <input type="text" id="register-username" name="username" required class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500">
                    </div>
                    
                    <div class="mb-4">
                        <label for="register-email" class="block text-sm font-medium mb-2">Email</label>
                        <input type="email" id="register-email" name="email" required class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500">
                    </div>
                    
                    <div class="mb-4">
                        <label for="register-password" class="block text-sm font-medium mb-2">Password</label>
                        <input type="password" id="register-password" name="password" required class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500">
                    </div>
                    
                    <div class="mb-4">
                        <label for="register-birthdate" class="block text-sm font-medium mb-2">Birthdate</label>
                        <input type="date" id="register-birthdate" name="birthdate" required class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500">
                    </div>
                    
                    <div class="mb-4">
                        <label for="register-bio" class="block text-sm font-medium mb-2">Bio</label>
                        <textarea id="register-bio" name="bio" rows="3" class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"></textarea>
                    </div>
                    
                    <div class="mb-4">
                        <label for="register-inactive-days" class="block text-sm font-medium mb-2">Inactive Days Threshold</label>
                        <p class="text-xs text-slate-400 mb-2">After how many days of inactivity should your account be marked as inactive?</p>
                        <input type="number" id="register-inactive-days" name="inactive_days" min="30" value="365" class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500">
                    </div>
                    
                    <div class="mb-4">
                        <label for="register-posthumous-letter" class="block text-sm font-medium mb-2">Posthumous Letter</label>
                        <p class="text-xs text-slate-400 mb-2">This message will be displayed when your account is marked as inactive.</p>
                        <textarea id="register-posthumous-letter" name="posthumous_letter" rows="4" class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"></textarea>
                    </div>
                    
                    <div class="mb-6">
                        <label class="block text-sm font-medium mb-2">Interests (Select at least one)</label>
                        <div class="grid grid-cols-2 gap-2">
                            <?php foreach ($categories as $key => $name): ?>
                                <label class="flex items-center space-x-2">
                                    <input type="checkbox" name="categories[]" value="<?= htmlspecialchars($key) ?>" class="rounded bg-slate-700 border-slate-600 text-purple-500 focus:ring-purple-500">
                                    <span><?= htmlspecialchars($name) ?></span>
                                </label>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    
                    <div class="flex items-center justify-between">
                        <button type="submit" class="px-4 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition">Register</button>
                        <button type="button" onclick="document.getElementById('register-modal').classList.add('hidden'); document.getElementById('login-modal').classList.remove('hidden')" class="text-purple-400 hover:text-purple-300 text-sm">
                            Already have an account? Login
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Create Post Modal -->
    <?php if (isset($_SESSION['user'])): ?>
        <div id="create-post-modal" class="fixed inset-0 bg-black bg-opacity-50 z-50 hidden flex items-center justify-center p-4">
            <div class="bg-slate-800 rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
                <div class="p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-xl font-bold">Create New Post</h3>
                        <button onclick="document.getElementById('create-post-modal').classList.add('hidden')" class="text-slate-400 hover:text-white">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    
                    <form action="" method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="action" value="create_post">
                        
                        <div class="mb-4">
                            <label for="post-title" class="block text-sm font-medium mb-2">Title</label>
                            <input type="text" id="post-title" name="title" required maxlength="100" class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500">
                        </div>
                        
                        <div class="mb-4">
                            <label for="post-category" class="block text-sm font-medium mb-2">Category</label>
                            <select id="post-category" name="category" required class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500">
                                <option value="">Select a category</option>
                                <?php foreach ($categories as $key => $name): ?>
                                    <option value="<?= htmlspecialchars($key) ?>"><?= htmlspecialchars($name) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        
                        <div class="mb-4">
                            <label for="post-content" class="block text-sm font-medium mb-2">Content (max <?= MAX_POST_LENGTH ?> characters)</label>
                            <textarea id="post-content" name="content" rows="6" required maxlength="<?= MAX_POST_LENGTH ?>" class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"></textarea>
                            <div class="text-xs text-slate-400 mt-1 flex justify-between">
                                <span>Formatting: **bold**, _italic_, `code`</span>
                                <span id="char-count">0/<?= MAX_POST_LENGTH ?></span>
                            </div>
                        </div>
                        
                        <div class="mb-6">
                            <label for="post-image" class="block text-sm font-medium mb-2">Image (optional, max 1MB)</label>
                            <input type="file" id="post-image" name="image" accept="image/jpeg,image/png,image/gif" class="w-full text-sm text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-purple-600 file:text-white hover:file:bg-purple-700">
                            <p class="text-xs text-slate-400 mt-1">Supported formats: JPG, PNG, GIF (max 1MB)</p>
                        </div>
                        
                        <div class="flex justify-end">
                            <button type="submit" class="px-6 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition">Post</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    <?php endif; ?>
    
    <!-- Profile Settings Modal -->
    <?php if (isset($_SESSION['user'])): ?>
        <div id="profile-modal" class="fixed inset-0 bg-black bg-opacity-50 z-50 hidden flex items-center justify-center p-4">
            <div class="bg-slate-800 rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
                <div class="p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-xl font-bold">Edit Profile</h3>
                        <button onclick="document.getElementById('profile-modal').classList.add('hidden')" class="text-slate-400 hover:text-white">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    
                    <form action="" method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="action" value="update_profile">
                        
                        <div class="flex flex-col md:flex-row gap-6 mb-6">
                            <div class="md:w-1/3 flex flex-col items-center">
                                <?php if ($_SESSION['user']['avatar']): ?>
                                    <img src="<?= htmlspecialchars($_SESSION['user']['avatar']) ?>" alt="Current Avatar" class="w-32 h-32 rounded-full object-cover mb-4 border-4 border-purple-500">
                                <?php else: ?>
                                    <div class="w-32 h-32 rounded-full bg-purple-600 flex items-center justify-center mb-4 border-4 border-purple-500">
                                        <i class="fas fa-user text-white text-4xl"></i>
                                    </div>
                                <?php endif; ?>
                                
                                <label for="avatar-upload" class="px-4 py-2 bg-slate-700 text-white rounded-md hover:bg-slate-600 transition cursor-pointer text-center">
                                    <i class="fas fa-camera mr-2"></i> Change Avatar
                                    <input type="file" id="avatar-upload" name="avatar" accept="image/jpeg,image/png" class="hidden">
                                </label>
                                <p class="text-xs text-slate-400 mt-2">JPG or PNG, max 1MB</p>
                            </div>
                            
                            <div class="md:w-2/3">
                                <div class="mb-4">
                                    <label class="block text-sm font-medium mb-2">Username</label>
                                    <div class="px-3 py-2 bg-slate-700 rounded-md"><?= htmlspecialchars($_SESSION['user']['username']) ?></div>
                                </div>
                                
                                <div class="mb-4">
                                    <label class="block text-sm font-medium mb-2">Email</label>
                                    <div class="px-3 py-2 bg-slate-700 rounded-md"><?= htmlspecialchars($_SESSION['user']['email']) ?></div>
                                </div>
                                
                                <div class="mb-4">
                                    <label for="profile-bio" class="block text-sm font-medium mb-2">Bio</label>
                                    <textarea id="profile-bio" name="bio" rows="3" class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"><?= htmlspecialchars($_SESSION['user']['bio']) ?></textarea>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mb-4">
                            <label for="profile-inactive-days" class="block text-sm font-medium mb-2">Inactive Days Threshold</label>
                            <p class="text-xs text-slate-400 mb-2">After how many days of inactivity should your account be marked as inactive?</p>
                            <input type="number" id="profile-inactive-days" name="inactive_days" min="30" value="<?= htmlspecialchars($_SESSION['user']['inactive_days']) ?>" class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500">
                        </div>
                        
                        <div class="mb-4">
                            <label for="profile-posthumous-letter" class="block text-sm font-medium mb-2">Posthumous Letter</label>
                            <p class="text-xs text-slate-400 mb-2">This message will be displayed when your account is marked as inactive.</p>
                            <textarea id="profile-posthumous-letter" name="posthumous_letter" rows="4" class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"><?= htmlspecialchars($_SESSION['user']['posthumous_letter']) ?></textarea>
                        </div>
                        
                        <div class="mb-6">
                            <label class="block text-sm font-medium mb-2">Interests</label>
                            <div class="grid grid-cols-2 gap-2">
                                <?php foreach ($categories as $key => $name): ?>
                                    <label class="flex items-center space-x-2">
                                        <input type="checkbox" name="categories[]" value="<?= htmlspecialchars($key) ?>" <?= in_array($key, $_SESSION['user']['target_categories'] ?? []) ? 'checked' : '' ?> class="rounded bg-slate-700 border-slate-600 text-purple-500 focus:ring-purple-500">
                                        <span><?= htmlspecialchars($name) ?></span>
                                    </label>
                                <?php endforeach; ?>
                            </div>
                        </div>
                        
                        <div class="flex justify-end">
                            <button type="submit" class="px-6 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition">Save Changes</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    <?php endif; ?>
    
    <!-- App Settings Modal -->
    <?php if (isset($_SESSION['user'])): ?>
        <div id="settings-modal" class="fixed inset-0 bg-black bg-opacity-50 z-50 hidden flex items-center justify-center p-4">
            <div class="bg-slate-800 rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
                <div class="p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-xl font-bold">Settings</h3>
                        <button onclick="document.getElementById('settings-modal').classList.add('hidden')" class="text-slate-400 hover:text-white">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    
                    <div class="space-y-6">
                        <div>
                            <h4 class="text-lg font-semibold mb-3">Interface</h4>
                            <div class="space-y-4">
                                <div class="flex items-center justify-between">
                                    <span>Dark Mode</span>
                                    <label class="relative inline-flex items-center cursor-pointer">
                                        <input type="checkbox" checked class="sr-only peer">
                                        <div class="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                                    </label>
                                </div>
                                
                                <div class="flex items-center justify-between">
                                    <span>Animation Effects</span>
                                    <label class="relative inline-flex items-center cursor-pointer">
                                        <input type="checkbox" checked class="sr-only peer">
                                        <div class="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                                    </label>
                                </div>
                                
                                <div>
                                    <label class="block text-sm font-medium mb-2">Theme Color</label>
                                    <div class="flex space-x-2">
                                        <button class="w-8 h-8 rounded-full bg-purple-600 border-2 border-transparent hover:border-white"></button>
                                        <button class="w-8 h-8 rounded-full bg-blue-600 border-2 border-transparent hover:border-white"></button>
                                        <button class="w-8 h-8 rounded-full bg-red-600 border-2 border-transparent hover:border-white"></button>
                                        <button class="w-8 h-8 rounded-full bg-green-600 border-2 border-transparent hover:border-white"></button>
                                        <button class="w-8 h-8 rounded-full bg-yellow-600 border-2 border-transparent hover:border-white"></button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div>
                            <h4 class="text-lg font-semibold mb-3">Notifications</h4>
                            <div class="space-y-4">
                                <div class="flex items-center justify-between">
                                    <span>New Posts</span>
                                    <label class="relative inline-flex items-center cursor-pointer">
                                        <input type="checkbox" checked class="sr-only peer">
                                        <div class="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                                    </label>
                                </div>
                                
                                <div class="flex items-center justify-between">
                                    <span>Likes</span>
                                    <label class="relative inline-flex items-center cursor-pointer">
                                        <input type="checkbox" checked class="sr-only peer">
                                        <div class="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                                    </label>
                                </div>
                                
                                <div class="flex items-center justify-between">
                                    <span>Mentions</span>
                                    <label class="relative inline-flex items-center cursor-pointer">
                                        <input type="checkbox" checked class="sr-only peer">
                                        <div class="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                                    </label>
                                </div>
                            </div>
                        </div>
                        
                        <div>
                            <h4 class="text-lg font-semibold mb-3">Privacy</h4>
                            <div class="space-y-4">
                                <div class="flex items-center justify-between">
                                    <span>Show Online Status</span>
                                    <label class="relative inline-flex items-center cursor-pointer">
                                        <input type="checkbox" checked class="sr-only peer">
                                        <div class="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                                    </label>
                                </div>
                                
                                <div class="flex items-center justify-between">
                                    <span>Allow Direct Messages</span>
                                    <label class="relative inline-flex items-center cursor-pointer">
                                        <input type="checkbox" checked class="sr-only peer">
                                        <div class="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                                    </label>
                                </div>
                            </div>
                        </div>
                        
                        <div class="pt-4 border-t border-slate-700">
                            <button class="px-6 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition">Delete Account</button>
                            <p class="text-xs text-slate-400 mt-2">Warning: This action cannot be undone. All your data will be permanently deleted.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    <?php endif; ?>
    
    <script>
        // Character counter for post content
        const postContent = document.getElementById('post-content');
        const charCount = document.getElementById('char-count');
        
        if (postContent && charCount) {
            postContent.addEventListener('input', () => {
                charCount.textContent = `${postContent.value.length}/<?= MAX_POST_LENGTH ?>`;
            });
        }
        
        // Like post function
        function likePost(postId) {
            if (!<?= isset($_SESSION['user']) ? 'true' : 'false' ?>) {
                document.getElementById('login-modal').classList.remove('hidden');
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `action=like_post&post_id=${postId}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const likeBtn = document.querySelector(`.like-btn[onclick="likePost('${postId}')"]`);
                    const likeCount = likeBtn.querySelector('span');
                    
                    likeBtn.classList.toggle('liked');
                    likeCount.textContent = data.likes_count;
                }
            });
        }
        
        // Report post function
        function reportPost(postId) {
            if (!<?= isset($_SESSION['user']) ? 'true' : 'false' ?>) {
                document.getElementById('login-modal').classList.remove('hidden');
                return;
            }
            
            if (confirm('Are you sure you want to report this post?')) {
                fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=report_post&post_id=${postId}`
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        const reportBtn = document.querySelector(`.report-btn[onclick="reportPost('${postId}')"]`);
                        reportBtn.classList.add('reported');
                        alert('Post reported. Thank you for helping keep MHCN+ safe.');
                    }
                });
            }
        }
        
        // Preview avatar before upload
        const avatarUpload = document.getElementById('avatar-upload');
        if (avatarUpload) {
            avatarUpload.addEventListener('change', function(e) {
                const file = e.target.files[0];
                if (file) {
                    const reader = new FileReader();
                    reader.onload = function(event) {
                        const avatarPreview = document.querySelector('#profile-modal img');
                        if (avatarPreview) {
                            avatarPreview.src = event.target.result;
                        }
                    };
                    reader.readAsDataURL(file);
                }
            });
        }
    </script>
</body>
</html>