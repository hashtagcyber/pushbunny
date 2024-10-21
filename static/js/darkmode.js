document.addEventListener('DOMContentLoaded', (event) => {
    const darkModeToggle = document.getElementById('darkModeToggle');
    
    // Check for saved 'darkMode' in localStorage
    let darkMode = localStorage.getItem('darkMode'); 
    
    const enableDarkMode = () => {
        document.body.classList.add('dark-mode');
        localStorage.setItem('darkMode', 'enabled');
    }

    const disableDarkMode = () => {
        document.body.classList.remove('dark-mode');
        localStorage.setItem('darkMode', null);
    }
    
    // If the user already visited and enabled darkMode
    // start things off with it on
    if (darkMode === 'enabled') {
        enableDarkMode();
        darkModeToggle.checked = true;
    }

    // When someone clicks the button
    darkModeToggle.addEventListener('click', () => {
        darkMode = localStorage.getItem('darkMode'); 
        
        // if it not current enabled, enable it
        if (darkMode !== 'enabled') {
            enableDarkMode();
        // if it has been enabled, turn it off  
        } else {  
            disableDarkMode(); 
        }
    });
});
