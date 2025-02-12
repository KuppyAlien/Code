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
                        Vui lòng <button class="btn btn-edit" onclick="componentManager.showLoginDialog()">
                            đăng nhập
                        </button> để tương tác với linh kiện
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
            existingComponent.notes += `\nBổ sung ${componentData.quantity || 1} đơn vị vào ${new Date().toLocaleString('vi-VN')}`;
        } else {
            const newComponent = new Component(
                componentData.id,
                componentData.name,
                componentData.quantity || 1,
                componentData.location || 'Chưa xác định'
            );
            newComponent.notes = `Nhập kho lần đầu: ${componentData.quantity || 1} đơn vị`;
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

        const newQuantity = prompt('Nhập lượng hợp lệ:', component.quantity);
        const newLocation = prompt('Nhập vị trí hợp lệ:', component.location);

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
                <td>${component.dateIssued ? new Date(component.dateIssued).toLocaleString('vi-VN') : 'Chưa xuất'}</td>
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
            <h3>Đăng Nhập</h3>
            <div class="login-form">
                <div class="form-group">
                    <label for="userId">Mã người dùng:</label>
                    <input type="text" id="userId" placeholder="Nhập mã người dùng (VD: A1, R1)">
                </div>
                <div class="form-group">
                    <label for="passwordInput">Mật khẩu:</label>
                    <input type="password" id="passwordInput" placeholder="Nhập mật khẩu">
                    <button class="forgot-password-btn" onclick="componentManager.showForgotPasswordDialog()">
                        Quên mật khẩu?
                    </button>
                </div>
                <div class="error-message" id="loginError" style="display: none;"></div>
                <div class="dialog-buttons">
                    <button class="btn btn-edit">Đăng Nhập</button>
                    <button class="btn btn-delete">Hủy</button>
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

    login() {
        const userId = document.getElementById('userId').value;
        const password = document.getElementById('passwordInput').value;
        const errorElement = document.getElementById('loginError');
        
        if (!userId || !password) {
            errorElement.textContent = 'Vui lòng điền đầy đủ thông tin';
            errorElement.style.display = 'block';
            return;
        }

        const user = this.users.find(u => u.id === userId);
        
        if (!user || user.password !== password) {
            errorElement.textContent = 'Mã người dùng hoặc mật khẩu không đúng';
            errorElement.style.display = 'block';
            return;
        }

        this.currentUser = user;
        document.getElementById('loginStatus').textContent = `Đã đăng nhập với: ${user.name}`;
        document.querySelector('.login-dialog').remove();
        
        document.getElementById('logoutBtn').style.display = 'block';
        document.getElementById('loginBtn').style.display = 'none';
        
        this.showProfile();
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
        const token = localStorage.getItem('sessionToken');
        if (token) {
            this.sessions.delete(token);
            localStorage.removeItem('sessionToken');
        }
        this.currentUser = null;
        this.updateUIAfterLogout();
    }

    showProfile() {
        const profilePage = document.querySelector('.profile-page');
        const componentList = document.querySelector('.component-list');
        const requestsList = document.querySelector('.request-section');
        const scannerSection = document.querySelector('.scanner-section');
        const usersPage = document.querySelector('.users-page');

        // Hide all other sections except scanner
        componentList.style.display = 'none';
        requestsList.style.display = 'none';
        usersPage.style.display = 'none';
        scannerSection.style.display = 'block'; // Keep scanner visible

        // Show profile page
        profilePage.style.display = 'block';

        // Update profile information
        document.getElementById('profileId').textContent = this.currentUser.id;
        document.getElementById('profileName').textContent = this.currentUser.name;
        document.getElementById('profileRole').textContent = this.currentUser.role;
        document.getElementById('profilePhone').textContent = this.currentUser.phone;

        // Update request statistics
        this.updateRequestStats();
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
        const profilePage = document.querySelector('.profile-page');
        const componentList = document.querySelector('.component-list');
        const requestsList = document.querySelector('.request-section');
        const scannerSection = document.querySelector('.scanner-section');

        profilePage.style.display = 'none';
        componentList.style.display = 'block';
        scannerSection.style.display = 'block'; // Always show scanner
        
        if (this.currentUser.role === 'approver') {
            requestsList.style.display = 'block';
        } else {
            requestsList.style.display = 'none';
        }
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
            this.currentUser ? this.currentUser.name : 'Hồ sơ người dùng (Chưa đăng nhập)';
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
                            `<p>Người yêu cầu: ${requester ? requester.name : 'Unknown'}</p>` : 
                            ''
                        }
                        <p>Vật tư: ${component ? component.name : 'Unknown'}</p>
                        <p>Số lượng: ${request.quantity}</p>
                        <p>Trạng thái: ${statusNames[request.status]}</p>
                        <p>Lý do: ${request.reason || 'Không có lý do'}</p>
                        ${this.currentUser.role === 'approver' && request.status === 'pending' ? `
                            <div class="request-actions">
                                <button onclick="event.stopPropagation(); componentManager.handleRequest('${request.id}', 'approved')" class="btn btn-edit">
                                    Duyệt
                                </button>
                                <button onclick="event.stopPropagation(); componentManager.handleRequest('${request.id}', 'rejected')" class="btn btn-delete">
                                    Từ chối
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
                component.notes += `\nXuất ${request.quantity} đơn vị theo yêu cầu ${requestId}`;
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
                    `Đã đăng nhập với: ${newName}`;
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

    // Update the logout method
    logout() {
        this.currentUser = null;
        document.getElementById('loginStatus').textContent = 'Not logged in';
        document.getElementById('logoutBtn').style.display = 'none';
        document.getElementById('loginBtn').style.display = 'block';
        this.updateUIForCurrentUser();
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
        const approverList = document.getElementById('approverList');
        const requesterList = document.getElementById('requesterList');

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
            <h3>Request Scanned Component</h3>
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

        document.querySelector('.login-dialog').remove();
        alert('Request submitted successfully');
    }

    // Add showHomePage method to ComponentManager class
    showHomePage() {
        // Hide all sections first
        const sections = [
            '.profile-page',
            '.users-page',
            '.request-section',
            '.scanner-section',
            '#userManagement'
        ];
        
        sections.forEach(section => {
            document.querySelector(section).style.display = 'none';
        });

        // Show component list (main inventory view)
        const componentList = document.querySelector('.component-list');
        componentList.style.display = 'block';

        // If user is logged in and is approver, show requests section
        if (this.currentUser?.role === 'approver') {
            document.querySelector('.request-section').style.display = 'block';
        }

        // Show scanner section if logged in
        if (this.currentUser) {
            document.querySelector('.scanner-section').style.display = 'block';
        }
    }

    // Add to ComponentManager class
    toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        sidebar.classList.toggle('expanded');
    }

    // Add new method to ComponentManager class
    showAddComponentDialog() {
        if (!this.currentUser || this.currentUser.role !== 'approver') {
            alert('Chỉ người phê duyệt mới có thể thêm linh kiện');
            return;
        }

        const dialog = document.createElement('div');
        dialog.className = 'login-dialog add-component-dialog';
        dialog.innerHTML = `
            <h3>Thêm Linh Kiện Mới</h3>
            <div class="add-component-form">
                <div class="form-row">
                    <label for="componentId">Mã số:</label>
                    <input type="text" id="componentId" required 
                           placeholder="Nhập mã số linh kiện">
                </div>
                <div class="form-row">
                    <label for="componentName">Tên:</label>
                    <input type="text" id="componentName" required 
                           placeholder="Nhập tên linh kiện">
                </div>
                <div class="form-row">
                    <label for="componentQuantity">Số lượng:</label>
                    <input type="number" id="componentQuantity" required 
                           min="1" value="1">
                </div>
                <div class="form-row">
                    <label for="componentLocation">Vị trí:</label>
                    <input type="text" id="componentLocation" required 
                           placeholder="Nhập vị trí lưu trữ">
                </div>
                <div class="error-message" id="addComponentError" style="display: none;"></div>
                <div class="dialog-buttons">
                    <button class="btn btn-edit" onclick="componentManager.submitNewComponent()">
                        Thêm Linh Kiện
                    </button>
                    <button class="btn btn-delete" onclick="this.closest('.login-dialog').remove()">
                        Hủy
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(dialog);
    }

    // Add method to handle new component submission
    submitNewComponent() {
        const id = document.getElementById('componentId').value.trim();
        const name = document.getElementById('componentName').value.trim();
        const quantity = parseInt(document.getElementById('componentQuantity').value);
        const location = document.getElementById('componentLocation').value.trim();
        const errorElement = document.getElementById('addComponentError');

        // Validate inputs
        if (!id || !name || !location) {
            errorElement.textContent = 'Vui lòng điền đầy đủ thông tin';
            errorElement.style.display = 'block';
            return;
        }

        if (!quantity || quantity < 1) {
            errorElement.textContent = 'Vui lòng nhập số lượng hợp lệ';
            errorElement.style.display = 'block';
            return;
        }

        // Check for duplicate ID
        if (this.components.some(c => c.id === id)) {
            errorElement.textContent = 'Mã số này đã tồn tại';
            errorElement.style.display = 'block';
            return;
        }

        // Create and add new component
        const newComponent = new Component(id, name, quantity, location);
        newComponent.notes = `Nhập kho thủ công: ${quantity} đơn vị`;
        
        this.components.push(newComponent);
        this.saveToLocalStorage();
        this.renderComponentTable();

        // Close dialog and show success message
        document.querySelector('.login-dialog').remove();
        alert('Đã thêm linh kiện thành công');
    }

    // Add new method to handle user info click
    handleUserInfoClick() {
        if (this.currentUser) {
            this.showProfile();
        } else {
            this.showLoginDialog();
        }
    }

    // Add method to show request form
    showRequestForm(request) {
        const component = this.components.find(c => c.id === request.componentId);
        const requester = this.users.find(u => u.id === request.requesterId);
        const approver = this.users.find(u => u.role === 'approver');
        
        // Update form fields
        document.getElementById('requestDate').textContent = new Date(request.timestamp).toLocaleDateString('vi-VN');
        document.getElementById('requestId').textContent = request.id;
        document.getElementById('componentName').textContent = component.name;
        document.getElementById('requestQuantity').textContent = request.quantity;
        document.getElementById('requestReason').textContent = request.reason;
        
        // Update signatures
        document.getElementById('requesterName').textContent = requester.name;
        document.getElementById('requesterPosition').textContent = 'Người yêu cầu';
        document.getElementById('requesterSignDate').textContent = new Date(request.timestamp).toLocaleDateString('vi-VN');
        
        if (request.status === 'approved') {
            document.getElementById('approverName').textContent = approver.name;
            document.getElementById('approverPosition').textContent = 'Người phê duyệt';
            document.getElementById('approverSignDate').textContent = new Date().toLocaleDateString('vi-VN');
        }
        
        // Show form
        document.getElementById('requestFormTemplate').style.display = 'block';
    }
}

// Initialize the component manager
const componentManager = new ComponentManager();

// Update error messages
const errorMessages = {
    invalidCredentials: 'Mã người dùng hoặc mật khẩu không đúng',
    fillAllFields: 'Vui lòng điền đầy đủ thông tin',
    accountLocked: 'Tài khoản đã bị khóa. Vui lòng thử lại sau {minutes} phút',
    invalidQuantity: 'Vui lòng nhập số lượng hợp lệ',
    provideReason: 'Vui lòng cung cấp lý do yêu cầu',
    requestSuccess: 'Đã gửi yêu cầu thành công',
    loginRequired: 'Vui lòng đăng nhập để thực hiện thao tác này',
    invalidQRCode: 'Mã QR không hợp lệ',
    componentAdded: 'Đã thêm linh kiện vào kho!',
    scanSuccess: 'Quét mã thành công!'
};

// Update role names
const roleNames = {
    approver: 'Người phê duyệt',
    requester: 'Người yêu cầu'
};

// Update status names
const statusNames = {
    pending: 'Đang chờ',
    approved: 'Đã duyệt',
    rejected: 'Từ chối'
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
        name: 'Người Phê Duyệt',
        phone: '0123456789'
    },
    'requester': {
        password: '123456',
        role: 'requester',
        name: 'Người Yêu Cầu',
        phone: '0123456789'
    }
}; 