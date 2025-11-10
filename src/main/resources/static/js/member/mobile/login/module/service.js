const memberService = (() => {
    const login = async (member) => {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify(member),
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || "Fetch error");
        }

        return await response.json();
    }

    const guestLogin = async (member) => {
        const response = await fetch('/api/auth/guest-login', {
            method: 'POST',
            body: JSON.stringify(member),
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || "Fetch error");
        }

        return await response.json();
    }

    const refresh = async () => {
        const response = await fetch('/api/auth/refresh', {
            method: 'POST',
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || "Fetch error");
        }

        return await response.json();
    }

    const logout = async () => {
        const response = await fetch('/api/auth/logout', {
            method: 'POST',
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || "Fetch error");
        }
    }

    const info = async (callback) => {
        const response = await fetch('/api/auth/info');
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || "Fetch error");
        }

        const member = await response.json();

        if(callback) {
            callback(member);
        }
    }

    const resetCookies = async () => {
        const response = await fetch('/api/auth/reset-cookies', {
            method: 'POST',
        });
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || "Fetch error");
        }
    }



    return {login: login, guestLogin:guestLogin, refresh: refresh, logout: logout, info: info, resetCookies: resetCookies};
})();