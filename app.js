class SecurityUtils {
    static async hashPassword(password, salt = null) {
        const encoder = new TextEncoder();
        salt = salt || crypto.getRandomValues(new Uint8Array(16));
        const passwordData = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', 
            new Uint8Array([...salt, ...passwordData]));
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return { hash: hashHex, salt: Array.from(salt) };
    }

    static async verifyPassword(password, storedHash, storedSalt) {
        const { hash } = await this.hashPassword(password, new Uint8Array(storedSalt));
        return hash === storedHash;
    }

    static generateSessionToken() {
        return Array.from(crypto.getRandomValues(new Uint8Array(32)))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    }

    static sanitizeInput(input) {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    }

    static validatePassword(password) {
        const errors = [];
        if (password.length < 7) {
            errors.push('Password must be at least 7 characters long');
        }
        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter');
        }
        if (!/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter');
        }
        if (!/\d/.test(password)) {
            errors.push('Password must contain at least one number');
        }
        return errors;
    }
}

class User {
    constructor(id, name, role, password, phone) {
        this.id = id;
        this.name = name;
        this.role = role; // 'approver' or 'requester'
        this.password = password;
        this.phone = phone;
    }
}

class Request {
    constructor(id, requesterId, componentId, quantity, status = 'pending') {
        this.id = id;
        this.requesterId = requesterId;
        this.componentId = componentId;
        this.quantity = quantity;
        this.status = status; // 'pending', 'approved', 'rejected'
        this.timestamp = new Date().toISOString();
    }
}

class Component {
    constructor(id, name, quantity, location) {
        this.id = id;
        this.name = name;
        this.quantity = quantity;
        this.location = location;
        this.dateAdded = new Date().toISOString(); // Ngày nhập
        this.dateIssued = null;  // Ngày xuất
        this.notes = '';  // Ghi chú
    }
}

class ComponentManager {
    constructor() {
        this.components = JSON.parse(localStorage.getItem('components')) || [];
        this.users = JSON.parse(localStorage.getItem('users')) || this.initializeUsers();
        this.requests = JSON.parse(localStorage.getItem('requests')) || [];
        this.currentUser = null;
        
        this.sessions = new Map();
        this.loginAttempts = new Map();
        this.initScanner();
        this.initEventListeners();
        this.renderComponentTable();
        this.renderUsers();
        this.renderRequests();
        this.initSecuritySettings();
        this.savedForms = JSON.parse(localStorage.getItem('savedForms')) || [];
        this.signaturePads = new Map(); // Store signature pad instances
        this.notifications = [];
        this.initNotifications();
    }

    initScanner() {
        const html5QrcodeScanner = new Html5QrcodeScanner(
            "reader", { fps: 10, qrbox: 250 });
            
        document.getElementById('startCameraBtn').addEventListener('click', () => {
            document.getElementById('reader').style.display = 'block';
            document.getElementById('startCameraBtn').style.display = 'none';
            
            html5QrcodeScanner.render((decodedText, decodedResult) => {
                this.handleQRCodeScan(decodedText);
            });
        });
    }

    initEventListeners() {
        document.getElementById('searchInput').addEventListener('input', (e) => {
            this.filterComponents(e.target.value);
        });
        document.getElementById('loginBtn').addEventListener('click', () => this.showLoginDialog());
        document.getElementById('usersBtn').addEventListener('click', () => this.showUsersPage());
    }

    handleQRCodeScan(decodedText) {
        try {
            const componentData = JSON.parse(decodedText);
            
            if (!this.currentUser) {
                // Not logged in - show login prompt
                document.getElementById('result').innerHTML = 
                    `<p style="color: var(--primary-color)">
                        Please <button class="btn btn-edit" onclick="componentManager.showLoginDialog()">
                            login
                        </button> to interact with the component
                    </p>`;
                return;
            }
            
            if (this.currentUser.role === 'approver') {
                // Approvers can add components
                this.addComponent(componentData);
                document.getElementById('result').innerHTML = 
                    `<p style="color: var(--success-color)">${this.errorMessages.componentAdded}</p>`;
            } else if (this.currentUser.role === 'requester') {
                // Requesters can only make requests
                this.showScanRequestDialog(componentData);
                document.getElementById('result').innerHTML = 
                    `<p style="color: var(--success-color)">${this.errorMessages.scanSuccess}</p>`;
            }
        } catch (error) {
            document.getElementById('result').innerHTML = 
                `<p style="color: var(--danger-color)">${this.errorMessages.invalidQRCode}</p>`;
        }
    }

    addComponent(componentData) {
        const existingComponent = this.components.find(c => c.id === componentData.id);
        
        if (existingComponent) {
            existingComponent.quantity += componentData.quantity || 1;
            existingComponent.notes += `\nAdded ${componentData.quantity || 1} units to ${new Date().toLocaleString('vi-VN')}`;
        } else {
            const newComponent = new Component(
                componentData.id,
                componentData.name,
                componentData.quantity || 1,
                componentData.location || 'Unspecified'
            );
            newComponent.notes = `First entry: ${componentData.quantity || 1} units`;
            this.components.push(newComponent);
        }
        
        this.saveToLocalStorage();
        this.renderComponentTable();
    }

    deleteComponent(id) {
        this.components = this.components.filter(c => c.id !== id);
        this.saveToLocalStorage();
        this.renderComponentTable();
    }

    editComponent(id) {
        const component = this.components.find(c => c.id === id);
        if (!component) return;

        const newQuantity = prompt('Enter a valid quantity:', component.quantity);
        const newLocation = prompt('Enter a valid location:', component.location);

        if (newQuantity !== null && newLocation !== null) {
            component.quantity = parseInt(newQuantity) || component.quantity;
            component.location = newLocation;
            this.saveToLocalStorage();
            this.renderComponentTable();
        }
    }

    filterComponents(searchTerm) {
        const filteredComponents = this.components.filter(component => 
            component.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
            component.id.toLowerCase().includes(searchTerm.toLowerCase())
        );
        this.renderComponentTable(filteredComponents);
    }

    saveToLocalStorage() {
        localStorage.setItem('components', JSON.stringify(this.components));
    }

    renderComponentTable(componentsToRender = this.components) {
        const tableBody = document.getElementById('componentTableBody');
        tableBody.innerHTML = '';

        componentsToRender.forEach(component => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${component.id}</td>
                <td>${component.name}</td>
                <td>${component.quantity}</td>
                <td>${component.location}</td>
                <td>${new Date(component.dateAdded).toLocaleString('vi-VN')}</td>
                <td>${component.dateIssued ? new Date(component.dateIssued).toLocaleString('vi-VN') : 'Unused'}</td>
                <td>${component.notes}</td>
            `;
            tableBody.appendChild(row);
        });
    }

    initializeUsers() {
        const users = [];
        
        // Create 5 approvers with custom names, passwords, and phone numbers
        const approverNames = [
            { name: 'Quality Manager', phone: '+84123456789' },
            { name: 'Inventory Supervisor', phone: '+84123456790' },
            { name: 'Department Head', phone: '+84123456791' },
            { name: 'Senior Engineer', phone: '+84123456792' },
            { name: 'Project Manager', phone: '+84123456793' }
        ];
        
        approverNames.forEach((user, i) => {
            users.push(new User(
                `A${i + 1}`,
                user.name,
                'approver',
                `approver${i + 1}`,
                user.phone
            ));
        });

        // Create 10 requesters with custom names, passwords, and phone numbers
        const requesterNames = [
            { name: 'Assembly Tech 1', phone: '+84123456794' },
            { name: 'Assembly Tech 2', phone: '+84123456795' },
            { name: 'Maintenance Tech 1', phone: '+84123456796' },
            { name: 'Maintenance Tech 2', phone: '+84123456797' },
            { name: 'Production Staff 1', phone: '+84123456798' },
            { name: 'Production Staff 2', phone: '+84123456799' },
            { name: 'R&D Engineer 1', phone: '+84123456800' },
            { name: 'R&D Engineer 2', phone: '+84123456801' },
            { name: 'Test Engineer 1', phone: '+84123456802' },
            { name: 'Test Engineer 2', phone: '+84123456803' }
        ];
        
        requesterNames.forEach((user, i) => {
            users.push(new User(
                `R${i + 1}`,
                user.name,
                'requester',
                `requester${i + 1}`,
                user.phone
            ));
        });

        localStorage.setItem('users', JSON.stringify(users));
        this.users = users;
        this.renderUsers();
        return users;
    }

    showLoginDialog() {
        const dialog = document.createElement('div');
        dialog.className = 'login-dialog';
        dialog.innerHTML = `
            <div class="login-content">
                <h3>Login</h3>
                <div class="form-group">
                    <label for="userId">User ID:</label>
                    <input type="text" id="userId" placeholder="Enter user ID">
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" placeholder="Enter password">
                </div>
                <div class="error-message" id="loginError" style="display: none;"></div>
                <div class="dialog-buttons">
                    <button class="btn btn-edit" onclick="componentManager.login()">
                        Login
                    </button>
                    <button class="btn btn-delete" onclick="this.closest('.login-dialog').remove()">
                        Cancel
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(dialog);
    }

    initSecuritySettings() {
        this.MAX_LOGIN_ATTEMPTS = 5;
        this.LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes
        this.SESSION_DURATION = 30 * 60 * 1000; // 30 minutes
        this.PASSWORD_MIN_LENGTH = 8;
        this.PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

        // Start session cleanup interval
        setInterval(() => this.cleanupExpiredSessions(), 5 * 60 * 1000);
    }

    login(userId, password) {
        const user = users[userId];
        if (user && user.password === password) {
            // Set current user
            localStorage.setItem('currentUser', JSON.stringify({
                id: userId,
                name: user.name,
                role: user.role,
                phone: user.phone
            }));

            // Update UI
            document.getElementById('loginStatus').textContent = `Welcome, ${user.name}`;
            document.getElementById('loginBtn').style.display = 'none';
            document.getElementById('logoutBtn').style.display = 'inline-block';
            
            // Show profile page immediately after login
            this.showProfilePage();

            // Show admin-only buttons if user is admin
            if (user.role === 'admin') {
                document.getElementById('usersBtn').style.display = 'inline-block';
            }

            this.showNotification('Login successful!', 'success');
        } else {
            this.showNotification(errorMessages.invalidCredentials, 'error');
        }
    }

    isUserLocked(user) {
        return user.lockoutUntil && user.lockoutUntil > Date.now();
    }

    handleFailedLogin(user) {
        user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
        user.lastLoginAttempt = Date.now();

        if (user.failedLoginAttempts >= this.MAX_LOGIN_ATTEMPTS) {
            user.lockoutUntil = Date.now() + this.LOCKOUT_DURATION;
        }

        this.saveUsers();
    }

    cleanupExpiredSessions() {
        const now = Date.now();
        for (const [token, session] of this.sessions) {
            if (session.expires <= now) {
                this.sessions.delete(token);
            }
        }
    }

    validateSession() {
        const token = localStorage.getItem('sessionToken');
        if (!token) return false;

        const session = this.sessions.get(token);
        if (!session || session.expires <= Date.now()) {
            this.sessions.delete(token);
            localStorage.removeItem('sessionToken');
            return false;
        }

        // Extend session
        session.expires = Date.now() + this.SESSION_DURATION;
        return true;
    }

    logout() {
        localStorage.removeItem('currentUser');
        document.getElementById('loginStatus').textContent = 'Not logged in';
        document.getElementById('loginBtn').style.display = 'inline-block';
        document.getElementById('logoutBtn').style.display = 'none';
        document.getElementById('profileBtn').style.display = 'none';
        document.getElementById('usersBtn').style.display = 'none';
        
        // Return to home page
        this.showHomePage();
        
        this.showNotification('Logout successful!', 'success');
    }

    showProfilePage() {
        this.hideAllComponents();
        const currentUser = this.getCurrentUser();
        
        if (!currentUser) {
            this.showNotification('Please login to view profile', 'error');
            return;
        }

        // Show and update profile page
        const profilePage = document.querySelector('.profile-page');
        profilePage.style.display = 'block';

        // Update profile information
        document.getElementById('profileId').textContent = currentUser.id;
        document.getElementById('profileName').textContent = currentUser.name;
        document.getElementById('profileRole').textContent = this.getRoleDisplay(currentUser.role);
        document.getElementById('profilePhone').textContent = currentUser.phone;
    }

    hideAllComponents() {
        // Hide all main components
        const components = [
            '.profile-page',
            '.user-management',
            '.scanner-section',
            '.component-list',
            '.request-section',  // Add request materials section
            '.users-page',
            '#requestFormTemplate'  // Add request form template
        ];
        
        components.forEach(selector => {
            const element = document.querySelector(selector);
            if (element) element.style.display = 'none';
        });
    }

    updateRequestStats() {
        const userRequests = this.requests.filter(request => 
            request.requesterId === this.currentUser.id
        );

        document.getElementById('totalRequests').textContent = userRequests.length;
        document.getElementById('pendingRequests').textContent = 
            userRequests.filter(r => r.status === 'pending').length;
        document.getElementById('approvedRequests').textContent = 
            userRequests.filter(r => r.status === 'approved').length;
        document.getElementById('rejectedRequests').textContent = 
            userRequests.filter(r => r.status === 'rejected').length;
    }

    showInventory() {
        // Hide other components
        this.hideAllComponents();
        
        // Show inventory section
        const componentList = document.querySelector('.component-list');
        if (componentList) {
            componentList.style.display = 'block';
        }
        
        // Render component table
        this.renderComponentTable();
    }

    renderComponentTable() {
        const tbody = document.getElementById('componentTableBody');
        const searchTerm = document.getElementById('searchInput').value.toLowerCase();
        
        const filteredComponents = this.components.filter(component => 
            component.id.toLowerCase().includes(searchTerm) ||
            component.name.toLowerCase().includes(searchTerm)
        );
        
        tbody.innerHTML = filteredComponents.map(component => `
            <tr>
                <td>${component.id}</td>
                <td>${component.name}</td>
                <td>${component.quantity}</td>
                <td>${component.location}</td>
                <td>${new Date(component.dateAdded).toLocaleDateString('vi-VN')}</td>
                <td>${component.dateIssued ? new Date(component.dateIssued).toLocaleDateString('vi-VN') : '-'}</td>
                <td>${component.notes || '-'}</td>
            </tr>
        `).join('');
    }

    updateUIForCurrentUser() {
        const userManagement = document.getElementById('userManagement');
        const requestsList = document.querySelector('.request-section');
        const componentList = document.querySelector('.component-list');
        const scannerSection = document.querySelector('.scanner-section');

        if (this.currentUser) {
            if (this.currentUser.role === 'approver') {
                // Approver view
                userManagement.style.display = 'none';
                requestsList.style.display = 'block';
                componentList.style.display = 'block';
            } else {
                // Requester view
                userManagement.style.display = 'none';
                requestsList.style.display = 'none';
                componentList.style.display = 'block';
            }
        } else {
            // Not logged in view - only show scanner
            userManagement.style.display = 'none';
            requestsList.style.display = 'none';
            componentList.style.display = 'none';
        }
        
        // Always show scanner section
        scannerSection.style.display = 'block';

        // Update sidebar user info
        document.getElementById('sidebarUserName').textContent = 
            this.currentUser ? this.currentUser.name : 'User Profile (Not logged in)';
        document.getElementById('sidebarUserRole').textContent = 
            this.currentUser ? roleNames[this.currentUser.role] : '';
        
        // Show/hide admin menu
        document.getElementById('adminMenu').style.display = 
            this.currentUser?.role === 'approver' ? 'block' : 'none';
    }

    renderRequests() {
        const requestsList = document.getElementById('requestsList');
        let filteredRequests = this.requests;

        // Filter requests based on user role
        if (this.currentUser.role === 'requester') {
            filteredRequests = this.requests.filter(request => 
                request.requesterId === this.currentUser.id
            );
        }

        requestsList.innerHTML = filteredRequests
            .map(request => {
                const requester = this.users.find(u => u.id === request.requesterId);
                const component = this.components.find(c => c.id === request.componentId);
                
                return `
                    <div class="request-item" onclick="componentManager.showRequestForm(${JSON.stringify(request).replace(/"/g, '&quot;')})">
                        ${this.currentUser.role === 'approver' ? 
                            `<p>Requester: ${requester ? requester.name : 'Unknown'}</p>` : 
                            ''
                        }
                        <p>Component: ${component ? component.name : 'Unknown'}</p>
                        <p>Quantity: ${request.quantity}</p>
                        <p>Status: ${statusNames[request.status]}</p>
                        <p>Reason: ${request.reason || 'No reason provided'}</p>
                        ${this.currentUser.role === 'approver' && request.status === 'pending' ? `
                            <div class="request-actions">
                                <button onclick="event.stopPropagation(); componentManager.handleRequest('${request.id}', 'approved')" class="btn btn-edit">
                                    Approve
                                </button>
                                <button onclick="event.stopPropagation(); componentManager.handleRequest('${request.id}', 'rejected')" class="btn btn-delete">
                                    Reject
                                </button>
                            </div>
                        ` : ''}
                    </div>
                `;
            })
            .join('');
    }

    handleRequest(requestId, status) {
        const request = this.requests.find(r => r.id === requestId);
        if (!request) return;

        request.status = status;
        
        if (status === 'approved') {
            const component = this.components.find(c => c.id === request.componentId);
            if (component) {
                component.quantity -= request.quantity;
                component.dateIssued = new Date().toISOString();
                component.notes += `\nIssued ${request.quantity} units on request ${requestId}`;
                this.saveToLocalStorage();
            }
        }

        localStorage.setItem('requests', JSON.stringify(this.requests));
        this.renderRequests();
        this.renderComponentTable();
    }

    renderUsers() {
        const approversList = document.getElementById('approversList');
        const requestersList = document.getElementById('requestersList');
        
        approversList.innerHTML = this.users
            .filter(u => u.role === 'approver')
            .map(user => this.createUserListItem(user))
            .join('');

        requestersList.innerHTML = this.users
            .filter(u => u.role === 'requester')
            .map(user => this.createUserListItem(user))
            .join('');
    }

    createUserListItem(user) {
        return `
            <li class="user-item">
                <span>${user.name}</span>
                <div class="user-actions">
                    <button class="btn" onclick="componentManager.renameUser('${user.id}')">
                        Rename
                    </button>
                    <button class="btn" onclick="componentManager.changePassword('${user.id}')">
                        Change Password
                    </button>
                </div>
            </li>
        `;
    }

    renameUser(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return;

        // Create a more user-friendly rename dialog
        const dialog = document.createElement('div');
        dialog.className = 'login-dialog';
        dialog.innerHTML = `
            <h3>Rename User</h3>
            <p>Current name: ${user.name}</p>
            <input type="text" id="newNameInput" value="${user.name}" 
                   placeholder="Enter new name">
            <div class="dialog-buttons">
                <button class="btn btn-edit" onclick="componentManager.confirmRename('${userId}')">
                    Save
                </button>
                <button class="btn btn-delete" onclick="this.closest('.login-dialog').remove()">
                    Cancel
                </button>
            </div>
        `;
        
        document.body.appendChild(dialog);
    }

    confirmRename(userId) {
        const newNameInput = document.getElementById('newNameInput');
        const newName = newNameInput.value.trim();
        
        if (newName) {
            const user = this.users.find(u => u.id === userId);
            user.name = newName;
            this.saveUsers();
            this.renderUsers();
            
            // Update current user display if this is the logged-in user
            if (this.currentUser && this.currentUser.id === userId) {
                document.getElementById('loginStatus').textContent = 
                    `Logged in as: ${newName}`;
            }
        }
        
        // Remove the dialog
        document.querySelector('.login-dialog').remove();
    }

    createRequest(componentId, quantity) {
        if (!this.currentUser || this.currentUser.role !== 'requester') {
            alert('You must be logged in as a requester to create requests');
            return;
        }

        const request = new Request(
            `REQ${Date.now()}`,
            this.currentUser.id,
            componentId,
            quantity
        );

        this.requests.push(request);
        this.saveRequests();
        this.renderRequests();
    }

    saveUsers() {
        localStorage.setItem('users', JSON.stringify(this.users));
    }

    saveRequests() {
        localStorage.setItem('requests', JSON.stringify(this.requests));
    }

    // Update changePassword method to include instructions
    changePassword(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return;

        const dialog = document.createElement('div');
        dialog.className = 'login-dialog';
        dialog.innerHTML = `
            <h3>Change Password</h3>
            <p>User: ${user.name}</p>
            
            <div class="password-instructions">
                <p>Password requirements:</p>
                <ul>
                    <li>At least 7 characters long</li>
                    <li>Must contain at least one uppercase letter (A-Z)</li>
                    <li>Must contain at least one lowercase letter (a-z)</li>
                    <li>Must contain at least one number (0-9)</li>
                </ul>
            </div>

            <div class="form-group">
                <label for="currentPassword">Current Password:</label>
                <input type="password" id="currentPassword" placeholder="Enter current password">
            </div>
            <div class="form-group">
                <label for="newPassword">New Password:</label>
                <input type="password" id="newPassword" placeholder="Enter new password">
            </div>
            <div class="form-group">
                <label for="confirmPassword">Confirm Password:</label>
                <input type="password" id="confirmPassword" placeholder="Confirm new password">
            </div>
            <div class="error-message" id="passwordError" style="display: none;"></div>
            <div class="dialog-buttons">
                <button class="btn btn-edit" onclick="componentManager.confirmPasswordChange('${userId}')">
                    Save
                </button>
                <button class="btn btn-delete" onclick="this.closest('.login-dialog').remove()">
                    Cancel
                </button>
            </div>
        `;
        
        document.body.appendChild(dialog);
    }

    confirmPasswordChange(userId) {
        const currentPassword = document.getElementById('currentPassword').value;
        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        const errorElement = document.getElementById('passwordError');
        
        const user = this.users.find(u => u.id === userId);
        
        if (!await SecurityUtils.verifyPassword(currentPassword, user.passwordHash, user.salt)) {
            errorElement.textContent = 'Current password is incorrect';
            errorElement.style.display = 'block';
            return;
        }
        
        if (newPassword !== confirmPassword) {
            errorElement.textContent = 'New passwords do not match';
            errorElement.style.display = 'block';
            return;
        }
        
        if (newPassword.length < 6) {
            errorElement.textContent = 'Password must be at least 6 characters';
            errorElement.style.display = 'block';
            return;
        }
        
        const { hash, salt } = await SecurityUtils.hashPassword(newPassword);
        user.passwordHash = hash;
        user.salt = salt;
        this.saveUsers();
        document.querySelector('.login-dialog').remove();
        alert('Password changed successfully');
    }

    // Add method to show request dialog for requesters
    showRequestDialog(componentId) {
        if (!this.currentUser || this.currentUser.role !== 'requester') {
            alert('You must be logged in as a requester to create requests');
            return;
        }

        const component = this.components.find(c => c.id === componentId);
        if (!component) return;

        const dialog = document.createElement('div');
        dialog.className = 'login-dialog';
        dialog.innerHTML = `
            <h3>Request Component</h3>
            <p>Component: ${component.name}</p>
            <p>Available Quantity: ${component.quantity}</p>
            <div class="form-group">
                <label for="requestQuantity">Quantity:</label>
                <input type="number" id="requestQuantity" min="1" max="${component.quantity}" value="1">
            </div>
            <div class="error-message" id="requestError" style="display: none;"></div>
            <div class="dialog-buttons">
                <button class="btn btn-edit" onclick="componentManager.submitRequest('${componentId}')">
                    Submit Request
                </button>
                <button class="btn btn-delete" onclick="this.closest('.login-dialog').remove()">
                    Cancel
                </button>
            </div>
        `;
        
        document.body.appendChild(dialog);
    }

    // Add method to submit request
    submitRequest(componentId) {
        const quantityInput = document.getElementById('requestQuantity');
        const quantity = parseInt(quantityInput.value);
        const errorElement = document.getElementById('requestError');
        const component = this.components.find(c => c.id === componentId);

        if (!quantity || quantity < 1 || quantity > component.quantity) {
            errorElement.textContent = 'Please enter a valid quantity';
            errorElement.style.display = 'block';
            return;
        }

        this.createRequest(componentId, quantity);
        document.querySelector('.login-dialog').remove();
        alert('Request submitted successfully');
    }

    // Update the showForgotPasswordDialog method
    showForgotPasswordDialog() {
        const dialog = document.createElement('div');
        dialog.className = 'login-dialog';
        dialog.innerHTML = `
            <h3>Forgot Password</h3>
            <div class="login-form">
                <div class="form-group">
                    <label for="forgotPhone">Phone Number:</label>
                    <input type="tel" id="forgotPhone" 
                           placeholder="Enter your phone number (e.g., +84123456789)"
                           pattern="\\+\\d{11,12}">
                </div>
                <div class="error-message" id="forgotPasswordError" style="display: none;"></div>
                <div class="dialog-buttons">
                    <button class="btn btn-edit" onclick="componentManager.sendPasswordByPhone()">
                        Send Password
                    </button>
                    <button class="btn btn-delete" onclick="this.closest('.login-dialog').remove()">
                        Cancel
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(dialog);
    }

    // Add method to send password by phone
    sendPasswordByPhone() {
        const phoneInput = document.getElementById('forgotPhone');
        const errorElement = document.getElementById('forgotPasswordError');
        const phone = phoneInput.value.trim();
        
        // Validate phone number format
        const phoneRegex = /^\+\d{11,12}$/;
        if (!phoneRegex.test(phone)) {
            errorElement.textContent = 'Please enter a valid phone number (e.g., +84123456789)';
            errorElement.style.display = 'block';
            return;
        }

        // Find user by phone number
        const user = this.users.find(u => u.phone === phone);
        
        if (!user) {
            errorElement.textContent = 'No account found with this phone number';
            errorElement.style.display = 'block';
            return;
        }

        // Here you would integrate with an SMS service
        // For demo purposes, we'll show an alert
        alert(`Password would be sent to ${phone}\nFor demo: Your password is ${user.passwordHash}`);
        document.querySelector('.login-dialog').remove();
    }

    // Add method to show user settings dialog
    showUserSettingsDialog() {
        if (!this.currentUser) return;

        const dialog = document.createElement('div');
        dialog.className = 'login-dialog';
        dialog.innerHTML = `
            <h3>User Settings</h3>
            <div class="login-form">
                <div class="form-group">
                    <label>User ID: ${this.currentUser.id}</label>
                </div>
                <div class="form-group">
                    <label>Name: ${this.currentUser.name}</label>
                </div>
                <div class="form-group">
                    <label for="phoneNumber">Phone Number:</label>
                    <input type="tel" id="phoneNumber" value="${this.currentUser.phone}" 
                           placeholder="Enter phone number (e.g., +84123456789)">
                </div>
                <div class="settings-buttons">
                    <button class="btn btn-edit" onclick="componentManager.changePhoneNumber()">
                        Update Phone
                    </button>
                    <button class="btn btn-edit" onclick="componentManager.showChangePasswordDialog()">
                        Change Password
                    </button>
                </div>
                <div class="error-message" id="settingsError" style="display: none;"></div>
                <div class="dialog-buttons">
                    <button class="btn btn-delete" onclick="this.closest('.login-dialog').remove()">
                        Close
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(dialog);
    }

    // Add method to change phone number
    changePhoneNumber() {
        const phoneInput = document.getElementById('phoneNumber');
        const errorElement = document.getElementById('settingsError');
        const newPhone = phoneInput.value.trim();
        
        // Basic phone number validation
        const phoneRegex = /^\+\d{11,12}$/;
        if (!phoneRegex.test(newPhone)) {
            errorElement.textContent = 'Please enter a valid phone number (e.g., +84123456789)';
            errorElement.style.display = 'block';
            return;
        }

        this.currentUser.phone = newPhone;
        this.saveUsers();
        alert('Phone number updated successfully');
        document.querySelector('.login-dialog').remove();
    }

    // Add new method to show users page
    showUsersPage() {
        const usersPage = document.querySelector('.users-page');
        const componentList = document.querySelector('.component-list');
        const requestsList = document.querySelector('.request-section');
        const scannerSection = document.querySelector('.scanner-section');

        usersPage.style.display = 'block';
        componentList.style.display = 'none';
        requestsList.style.display = 'none';
        scannerSection.style.display = 'none';

        this.renderUsersPage();
    }

    // Add method to render users page
    renderUsersPage() {
        const approverList = document.getElementById('approversList');
        const requesterList = document.getElementById('requestersList');

        const renderUserCard = (user) => `
            <div class="user-card">
                <div class="user-info">
                    <span class="user-info-label">ID:</span>
                    <span class="user-info-value">${user.id}</span>
                    
                    <span class="user-info-label">Name:</span>
                    <span class="user-info-value">${user.name}</span>
                    
                    <span class="user-info-label">Phone:</span>
                    <span class="user-info-value">${user.phone}</span>
                </div>
                <div class="user-actions">
                    <button class="btn btn-edit" onclick="componentManager.renameUser('${user.id}')">
                        Rename
                    </button>
                    <button class="btn btn-edit" onclick="componentManager.changePassword('${user.id}')">
                        Change Password
                    </button>
                    <button class="btn btn-edit" onclick="componentManager.changeUserPhone('${user.id}')">
                        Update Phone
                    </button>
                </div>
            </div>
        `;

        approverList.innerHTML = this.users
            .filter(user => user.role === 'approver')
            .map(renderUserCard)
            .join('');

        requesterList.innerHTML = this.users
            .filter(user => user.role === 'requester')
            .map(renderUserCard)
            .join('');
    }

    // Add new method for scan request dialog
    showScanRequestDialog(componentData) {
        const component = this.components.find(c => c.id === componentData.id);
        if (!component) {
            alert('Component not found in inventory');
            return;
        }

        const dialog = document.createElement('div');
        dialog.className = 'login-dialog scan-request-dialog';
        dialog.innerHTML = `
            <h3>Scanned Component Request</h3>
            <div class="scanned-info">
                <div class="info-group">
                    <span class="info-label">Component:</span>
                    <span class="info-value">${component.name}</span>
                </div>
                <div class="info-group">
                    <span class="info-label">ID:</span>
                    <span class="info-value">${component.id}</span>
                </div>
                <div class="info-group">
                    <span class="info-label">Available:</span>
                    <span class="info-value">${component.quantity}</span>
                </div>
                <div class="info-group">
                    <span class="info-label">Location:</span>
                    <span class="info-value">${component.location}</span>
                </div>
            </div>
            <div class="form-group">
                <label for="scanRequestQuantity">Request Quantity:</label>
                <input type="number" id="scanRequestQuantity" 
                       min="1" max="${component.quantity}" value="1">
            </div>
            <div class="form-group">
                <label for="requestReason">Reason for Request:</label>
                <textarea id="requestReason" rows="3" 
                          placeholder="Please explain why you need this component..."></textarea>
            </div>
            <div class="error-message" id="scanRequestError" style="display: none;"></div>
            <div class="dialog-buttons">
                <button class="btn btn-edit" onclick="componentManager.submitScanRequest('${component.id}')">
                    Submit Request
                </button>
                <button class="btn btn-delete" onclick="this.closest('.login-dialog').remove()">
                    Cancel
                </button>
            </div>
        `;
        
        document.body.appendChild(dialog);
    }

    // Add method to submit scanned request
    submitScanRequest(componentId) {
        const quantityInput = document.getElementById('scanRequestQuantity');
        const reasonInput = document.getElementById('requestReason');
        const quantity = parseInt(quantityInput.value);
        const reason = reasonInput.value.trim();
        const errorElement = document.getElementById('scanRequestError');
        const component = this.components.find(c => c.id === componentId);

        // Validate inputs
        if (!quantity || quantity < 1 || quantity > component.quantity) {
            errorElement.textContent = 'Please enter a valid quantity';
            errorElement.style.display = 'block';
            return;
        }

        if (!reason) {
            errorElement.textContent = 'Please provide a reason for the request';
            errorElement.style.display = 'block';
            return;
        }

        // Create request with reason
        const request = new Request(
            `REQ${Date.now()}`,
            this.currentUser.id,
            componentId,
            quantity,
            'pending'
        );
        request.reason = reason;

        this.requests.push(request);
        localStorage.setItem('requests', JSON.stringify(this.requests));
        this.renderRequests();

        // Notify approvers
        this.notifyApprovers(request);

        document.querySelector('.login-dialog').remove();
        alert('Request submitted successfully');
    }

    // Add showHomePage method to ComponentManager class
    showHomePage() {
        this.hideAllComponents();
        
        // Show default components for home page
        const currentUser = this.getCurrentUser();
        
        if (currentUser) {
            // Show scanner section for all logged in users
            const scannerSection = document.querySelector('.scanner-section');
            if (scannerSection) scannerSection.style.display = 'block';
            
            // Show request section for approvers
            if (currentUser.role === 'approver') {
                const requestSection = document.querySelector('.request-section');
                if (requestSection) requestSection.style.display = 'block';
            }
        }
    }

    // Add updateSidebar method if not exists
    updateSidebar() {
        const sidebarUserName = document.getElementById('sidebarUserName');
        const sidebarUserRole = document.getElementById('sidebarUserRole');
        const adminMenu = document.getElementById('adminMenu');
        
        if (this.currentUser) {
            sidebarUserName.textContent = this.currentUser.name;
            sidebarUserRole.textContent = roleNames[this.currentUser.role] || this.currentUser.role;
            
            // Show/hide admin menu
            if (adminMenu) {
                adminMenu.style.display = this.currentUser.role === 'admin' ? 'block' : 'none';
            }
        } else {
            sidebarUserName.textContent = 'User Profile (Not logged in)';
            sidebarUserRole.textContent = '';
            if (adminMenu) {
                adminMenu.style.display = 'none';
            }
        }
    }

    // Add method to show request form
    showRequestForm(request) {
        const component = this.components.find(c => c.id === request.componentId);
        const requester = this.users.find(u => u.id === request.requesterId);
        const approver = this.users.find(u => u.role === 'approver');
        
        // Create form data object
        const formData = {
            id: request.id,
            date: new Date(request.timestamp).toLocaleDateString('vi-VN'),
            component: component.name,
            quantity: request.quantity,
            reason: request.reason,
            requester: {
                name: requester.name,
                position: 'Requester',
                date: new Date(request.timestamp).toLocaleDateString('vi-VN')
            },
            approver: request.status === 'approved' ? {
                name: approver.name,
                position: 'Approver',
                date: new Date().toLocaleDateString('vi-VN')
            } : null,
            status: request.status
        };

        // Save form to storage
        this.saveFormToStorage(formData);
        
        // Show form
        document.getElementById('requestFormTemplate').innerHTML = this.generateFormHTML(formData);
        document.getElementById('requestFormTemplate').style.display = 'flex';

        // Initialize signature pads after form is displayed
        setTimeout(() => {
            if (document.getElementById('requesterSignature')) {
                this.initSignaturePad('requesterSignature');
            }
            if (document.getElementById('approverSignature')) {
                this.initSignaturePad('approverSignature');
            }
        }, 100);
    }

    generateFormHTML(formData) {
        return `
        <div class="request-form">
            <div class="form-header">
                <img src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgdmlld0JveD0iMCAwIDEwMCAxMDAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxwYXRoIGQ9Ik0yMCAxMkg4MEw5MCA2MEgxMEwyMCAxMloiIHN0cm9rZT0iIzAwZjg4IiBzdHJva2Utd2lkdGg9IjIiLz4KPHBhdGggZD0iTTM1IDI1TDUwIDUwTDY1IDI1IiBzdHJva2U9IiMwMGZmODgiIHN0cm9rZS13aWR0aD0iMiIvPgo8dGV4dCB4PSI1MCIgeT0iODAiIGZvbnQtc2l6ZT0iMTIiIGZpbGw9IiMwMGZmODgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGxldHRlci1zcGFjaW5nPSIwLjNlbSI+diBpIGUgdCBoIHU8L3RleHQ+Cjwvc3ZnPg==" 
                     alt="VietPhu Logo" 
                     class="form-logo">
                <div class="form-meta">
                    <div class="form-number">Số: ${formData.id}</div>
                    <div class="form-date">Ngày: ${formData.date}</div>
                </div>
            </div>
            
            <h2 class="form-title">REQUEST FORM</h2>
            
            <div class="form-content">
                <div class="form-section">
                    <div class="form-row">
                        <label>Component:</label>
                        <span>${formData.component}</span>
                    </div>
                    <div class="form-row">
                        <label>Quantity:</label>
                        <span>${formData.quantity}</span>
                    </div>
                    <div class="form-row">
                        <label>Reason:</label>
                        <span>${formData.reason}</span>
                    </div>
                    <div class="form-row">
                        <label>Status:</label>
                        <span class="status-${formData.status}">${statusNames[formData.status]}</span>
                    </div>
                </div>
            </div>

            <div class="form-signatures">
                <div class="signature-section">
                    <p class="signature-title">Requester</p>
                    <div class="signature-box">
                        ${formData.requester.signature ? `
                            <img src="${formData.requester.signature}" class="saved-signature" alt="Requester Signature">
                        ` : this.currentUser.id === formData.requester.id ? `
                            <div class="signature-pad-container">
                                <canvas id="requesterSignature" class="signature-pad"></canvas>
                                <div class="signature-pad-actions">
                                    <button class="btn btn-small" id="requesterSignatureClear">
                                        Clear Signature
                                    </button>
                                </div>
                            </div>
                        ` : '<span class="pending">Pending</span>'}
                        <span class="signature-name">${formData.requester.name}</span>
                        <span class="signature-position">${formData.requester.position}</span>
                        <span class="signature-date">${formData.requester.date}</span>
                    </div>
                </div>
                
                <div class="signature-section">
                    <p class="signature-title">Approver</p>
                    <div class="signature-box">
                        ${formData.approver ? 
                            formData.approver.signature ? `
                                <img src="${formData.approver.signature}" class="saved-signature" alt="Approver Signature">
                            ` : this.currentUser.role === 'approver' ? `
                                <div class="signature-pad-container">
                                    <canvas id="approverSignature" class="signature-pad"></canvas>
                                    <div class="signature-pad-actions">
                                        <button class="btn btn-small" id="approverSignatureClear">
                                            Clear Signature
                                        </button>
                                    </div>
                                </div>
                            ` : '<span class="pending">Pending</span>'
                        : '<span class="pending">Pending Approval</span>'}
                        ${formData.approver ? `
                            <span class="signature-name">${formData.approver.name}</span>
                            <span class="signature-position">${formData.approver.position}</span>
                            <span class="signature-date">${formData.approver.date}</span>
                        ` : ''}
                    </div>
                </div>
            </div>

            <div class="form-actions">
                ${this.canSign(formData) ? `
                    <button class="btn btn-edit" onclick="componentManager.saveSignature('${formData.id}')">
                        Save Signature
                    </button>
                ` : ''}
                <button class="btn btn-edit" onclick="componentManager.printForm('${formData.id}')">
                    <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" fill="none">
                        <path d="M6 9V2h12v7M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2"/>
                        <path d="M6 14h12v8H6z"/>
                    </svg>
                    Print Form
                </button>
                <button class="btn btn-delete" onclick="document.getElementById('requestFormTemplate').style.display='none'">
                    Close
                </button>
            </div>
        </div>
        `;
    }

    canSign(formData) {
        if (!this.currentUser) return false;
        
        if (this.currentUser.id === formData.requester.id && !formData.requester.signature) {
            return true;
        }
        
        if (this.currentUser.role === 'approver' && 
            formData.status === 'pending' && 
            (!formData.approver || !formData.approver.signature)) {
            return true;
        }
        
        return false;
    }

    saveSignature(formId) {
        const form = this.savedForms.find(f => f.id === formId);
        if (!form) return;

        if (this.currentUser.id === form.requester.id) {
            const signaturePad = this.signaturePads.get('requesterSignature');
            if (signaturePad && !signaturePad.isEmpty()) {
                form.requester.signature = signaturePad.toDataURL();
            }
        } else if (this.currentUser.role === 'approver') {
            const signaturePad = this.signaturePads.get('approverSignature');
            if (signaturePad && !signaturePad.isEmpty()) {
                if (!form.approver) form.approver = {};
                form.approver.signature = signaturePad.toDataURL();
            }
        }

        this.saveFormToStorage(form);
        this.showRequestForm(form); // Refresh the form display
    }

    saveFormToStorage(formData) {
        // Add to saved forms array
        this.savedForms.push({
            ...formData,
            savedDate: new Date().toISOString()
        });
        
        // Keep only last 100 forms
        if (this.savedForms.length > 100) {
            this.savedForms = this.savedForms.slice(-100);
        }
        
        // Save to localStorage
        localStorage.setItem('savedForms', JSON.stringify(this.savedForms));
    }

    printForm(formId) {
        const form = this.savedForms.find(f => f.id === formId);
        if (!form) return;

        // Create printable version
        const printWindow = window.open('', '_blank');
        printWindow.document.write(`
            <html>
                <head>
                    <title>Request Form ${form.id}</title>
                    <style>
                        ${this.getPrintStyles()}
                    </style>
                </head>
                <body>
                    ${this.generateFormHTML(form)}
                </body>
            </html>
        `);
        printWindow.document.close();
        printWindow.print();
    }

    getPrintStyles() {
        return `
            /* Add print-specific styles here */
            @page {
                size: A4;
                margin: 2cm;
            }
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
            }
            .request-form {
                max-width: 100%;
                margin: 0;
                padding: 20px;
            }
            /* ... more print styles ... */
        `;
    }

    initSignaturePad(canvasId) {
        const canvas = document.getElementById(canvasId);
        const signaturePad = new SignaturePad(canvas, {
            backgroundColor: 'rgba(255, 255, 255, 0)',
            penColor: 'rgb(0, 168, 255)',
            velocityFilterWeight: 0.7,
        });
        
        this.signaturePads.set(canvasId, signaturePad);
        
        // Add clear button functionality
        const clearBtn = document.getElementById(`${canvasId}Clear`);
        if (clearBtn) {
            clearBtn.addEventListener('click', () => signaturePad.clear());
        }
        
        return signaturePad;
    }

    initNotifications() {
        // Create notification container if it doesn't exist
        if (!document.getElementById('notificationContainer')) {
            const container = document.createElement('div');
            container.id = 'notificationContainer';
            document.body.appendChild(container);
        }
    }

    notifyApprovers(request) {
        const component = this.components.find(c => c.id === request.componentId);
        const requester = this.users.find(u => u.id === request.requesterId);

        // Create notification
        const notification = {
            id: `NOTIFY${Date.now()}`,
            message: `New request from ${requester.name}: ${request.quantity} ${component.name}`,
            timestamp: new Date(),
            read: false,
            requestId: request.id
        };

        this.notifications.push(notification);
        this.showNotification(notification);

        // Store notifications
        localStorage.setItem('notifications', JSON.stringify(this.notifications));
    }

    showNotification(notification) {
        const container = document.getElementById('notificationContainer');
        const notificationElement = document.createElement('div');
        notificationElement.className = 'notification-toast';
        notificationElement.innerHTML = `
            <div class="notification-content">
                <div class="notification-header">
                    <svg class="notification-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" 
                              stroke-linecap="round" 
                              stroke-linejoin="round"/>
                        <path d="M12 11v6M9 14h6" 
                              stroke-linecap="round" 
                              stroke-linejoin="round"/>
                    </svg>
                    <span class="notification-title">New Request</span>
                </div>
                <p>${notification.message}</p>
                <div class="notification-actions">
                    <button class="btn btn-small btn-edit" 
                            onclick="componentManager.viewRequest('${notification.requestId}')">
                        View Details
                    </button>
                    <button class="btn btn-small" 
                            onclick="this.closest('.notification-toast').remove()">
                        Close
                    </button>
                </div>
            </div>
        `;

        container.appendChild(notificationElement);

        // Auto remove after 10 seconds
        setTimeout(() => {
            if (notificationElement.parentNode) {
                notificationElement.remove();
            }
        }, 10000);
    }

    viewRequest(requestId) {
        const request = this.requests.find(r => r.id === requestId);
        if (request) {
            this.showRequestForm(request);
        }
    }

    checkAdminAccess() {
        const currentUser = this.getCurrentUser();
        return currentUser && currentUser.role === 'admin';
    }

    showUserManagement() {
        if (!this.checkAdminAccess()) {
            this.showNotification('Only admin can access this section', 'error');
            return;
        }

        // Hide other components
        this.hideAllComponents();
        
        // Show user management section
        document.querySelector('.user-management').style.display = 'block';
        
        // Load users data
        this.loadUsers();
    }

    loadUsers() {
        // Example users data - replace with your actual data source
        const users = [
            { id: 'admin', name: 'Admin', role: 'admin', phone: '0123456789' },
            { id: 'user1', name: 'User 1', role: 'approver', phone: '0123456788' },
            // ... more users
        ];

        const tbody = document.getElementById('usersTableBody');
        tbody.innerHTML = '';

        users.forEach(user => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${user.id}</td>
                <td>${user.name}</td>
                <td>${this.getRoleDisplay(user.role)}</td>
                <td>${user.phone}</td>
                <td>
                    <button class="btn btn-small" onclick="componentManager.editUser('${user.id}')">
                        Edit
                    </button>
                    <button class="btn btn-small btn-danger" onclick="componentManager.deleteUser('${user.id}')">
                        Delete
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    getRoleDisplay(role) {
        const roles = {
            'admin': 'Administrator',
            'approver': 'Approver',
            'requester': 'Requester'
        };
        return roles[role] || role;
    }

    // Add these methods to handle user management
    showAddUserForm() {
        // Implement add user form
    }

    editUser(userId) {
        // Implement edit user
    }

    deleteUser(userId) {
        // Implement delete user
    }
}

// Initialize the component manager
const componentManager = new ComponentManager();

// Update error messages
const errorMessages = {
    invalidCredentials: 'Invalid user ID or password',
    fillAllFields: 'Please fill in all fields',
    accountLocked: 'Account is locked. Please try again in {minutes} minutes',
    invalidQuantity: 'Please enter a valid quantity',
    provideReason: 'Please provide a reason for the request',
    requestSuccess: 'Request sent successfully',
    loginRequired: 'Please login to perform this action',
    invalidQRCode: 'Invalid QR code',
    componentAdded: 'Component added to inventory!',
    scanSuccess: 'Scan successful!'
};

// Update role names
const roleNames = {
    admin: 'Administrator',
    approver: 'Approver',
    requester: 'Requester'
};

// Update status names
const statusNames = {
    pending: 'Pending',
    approved: 'Approved',
    rejected: 'Rejected'
};

const users = {
    'admin': {
        password: '123456',
        role: 'admin',
        name: 'Admin',
        phone: '0123456789'
    },
    'approver': {
        password: '123456',
        role: 'approver',
        name: 'Approver',
        phone: '0123456789'
    },
    'requester': {
        password: '123456',
        role: 'requester',
        name: 'Requester',
        phone: '0123456789'
    }
};

// Update notification messages
showNotification('Login successful!', 'success');
showNotification('Only admin can access this section', 'error');
showNotification('Logout successful!', 'success');
showNotification('Please login to view profile', 'error'); 