// Constants for main sections of the application
const SPLASH = document.querySelector(".splash");
const PROFILE = document.querySelector(".profile");
const LOGIN = document.querySelector(".login");
const CHAT = document.querySelector(".conversations");

// Selectors for dynamic elements
const USERNAME_DISPLAY = document.querySelectorAll('.username-info');
const LOGGED_OUT_BTN = document.querySelector(".loggedOut");
const LOGGED_IN_BTN = document.querySelector(".loggedIn");
const SIGNUP_BTN = document.querySelector(".signup");
const CREATE_ROOM_BTN = document.querySelector(".createRoomButton");
const CHANNEL_LIST = document.querySelector(".channelList");
const LOGIN_FAIL_MSG = document.querySelector("#loginfailmessage");

// Update display based on login status
function updateDisplay(isLoggedIn) {
  if (isLoggedIn) {
    LOGGED_OUT_BTN.classList.add("hide");
    SIGNUP_BTN.classList.add("hide");
    LOGGED_IN_BTN.classList.remove("hide");
    CREATE_ROOM_BTN.classList.remove("hide");
  } else {
    LOGGED_OUT_BTN.classList.remove("hide");
    SIGNUP_BTN.classList.remove("hide");
    LOGGED_IN_BTN.classList.add("hide");
    CREATE_ROOM_BTN.classList.add("hide");
  }
}

// Utility function to toggle UI elements based on user authentication
function toggleUIBasedOnAuth(isAuthenticated) {
    document.querySelectorAll('.loggedIn').forEach(elem => elem.style.display = isAuthenticated ? 'block' : 'none');
    document.querySelectorAll('.loggedOut').forEach(elem => elem.style.display = isAuthenticated ? 'none' : 'block');
    document.querySelector('.createRoomButton').style.display = isAuthenticated ? 'block' : 'none';
}

// Update displayed username
function updateUsername() {
    const username = localStorage.getItem('username');
    if (username) {
        USERNAME_DISPLAY.forEach(el => el.textContent = username);
    }
}

// Routing functionality to handle navigation
function router() {
    const path = window.location.pathname;
    const isAuthenticated = localStorage.getItem('isvalid') === 'true';

    toggleUIBasedOnAuth(isAuthenticated);
    updateUsername();

    // Hide all sections
    [SPLASH, PROFILE, LOGIN, CHAT].forEach(section => section.classList.add('hide'));

    // Route based on the path
    switch (path) {
        case '/':
            SPLASH.classList.remove('hide');
            break;
        case '/login':
            LOGIN.classList.remove('hide');
            break;
        case '/profile':
            PROFILE.classList.remove('hide');
            break;
        default:
            if (path.startsWith('/channel/')) {
                CHAT.classList.remove('hide');
                // Additional logic to display channel content
                loadChannelContent(path.split('/channel/')[1]);
            }
            break;
    }
}
  
// Authentication: Login
function login() {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    fetch('/api/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password})
    })
    .then(response => response.json())
    .then(data => {
        if (data.api_key) {
            localStorage.setItem('api_key', data.api_key);
            localStorage.setItem('isvalid', 'true');
            localStorage.setItem('username', username);
            toggleUIBasedOnAuth(true);
            window.location.pathname = '/';
        } else {
            LOGIN_FAIL_MSG.classList.remove('hide');
        }
    })
    .catch(error => console.error('Login Error:', error));
}
  
function signup() {
    const username = document.getElementById('signup-username').value;
    const password = document.getElementById('signup-password').value;

    fetch('/api/signup', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password})
    })
    .then(response => response.json())
    .then(data => {
        if (data.api_key) {
            // Successfully created user and obtained API key
            localStorage.setItem('api_key', data.api_key);
            localStorage.setItem('isvalid', 'true');
            localStorage.setItem('username', username);
            toggleUIBasedOnAuth(true);
            // Navigate to the splash or main chat area after signup
            window.location.pathname = '/';
        } else {
            // Handle errors or show message to user
            console.error('Signup failed:', data.message);
        }
    })
    .catch(error => {
        console.error('Signup Error:', error);
    });
}

function updateProfile() {
    const newUsername = document.getElementById('profile-username').value;
    const newPassword = document.getElementById('profile-password').value;
    const api_key = localStorage.getItem('api_key');

    fetch('/api/update_userinfo', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${api_key}`
        },
        body: JSON.stringify({username: newUsername, password: newPassword})
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Profile update was successful
            localStorage.setItem('username', newUsername);
            updateUsername();
            alert('Profile updated successfully');
            // Reload or navigate to reflect changes
            window.location.reload();
        } else {
            // Handle errors or show message to user
            console.error('Update Profile failed:', data.message);
        }
    })
    .catch(error => {
        console.error('Update Profile Error:', error);
    });
}

  
// Function to log out user
function logout() {
    localStorage.clear();
    updateDisplay(false);
    router();
}  
  
function loadChannelContent(channelId) {
    const api_key = localStorage.getItem('api_key');
    
    fetch(`/api/channels/${channelId}/messages`, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${api_key}`
        }
    })
    .then(response => response.json())
    .then(messages => {
        MESSAGE_LIST.innerHTML = ''; // Clear current messages
        messages.forEach(message => {
            // Create and append each message to the MESSAGE_LIST
            let messageElement = document.createElement('div');
            messageElement.classList.add('message');
            messageElement.innerHTML = `<strong>${message.author}</strong>: ${message.content}`;
            MESSAGE_LIST.appendChild(messageElement);
        });
    })
    .catch(error => {
        console.error('Error loading channel messages:', error);
    });
}
  
// Function to update displayed username
function updateUsername() {
    let username = localStorage.getItem('username');
    if (username) {
        USERNAME_DISPLAY.forEach(element => {
        element.textContent = username;
      });
    }
}
  
document.addEventListener('DOMContentLoaded', () => {
    router();
});