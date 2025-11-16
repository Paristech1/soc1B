// app.js
document.addEventListener('DOMContentLoaded', function() {
  // Theme Toggle
  const toggleBtn = document.querySelector('.theme-toggle');
  const body = document.body;
  
  // Load saved theme preference
  const savedTheme = localStorage.getItem('theme') || 'dark';
  body.classList.add(savedTheme);
  
  toggleBtn.addEventListener('click', function() {
    body.classList.toggle('dark');
    body.classList.toggle('light');
    
    // Save preference
    const currentTheme = body.classList.contains('dark') ? 'dark' : 'light';
    localStorage.setItem('theme', currentTheme);
  });

  // Lab Filter Functionality
  const filterBtns = document.querySelectorAll('.filter-btn');
  const labCards = document.querySelectorAll('.lab-card');

  filterBtns.forEach(btn => {
    btn.addEventListener('click', function() {
      // Remove active class from all buttons
      filterBtns.forEach(b => b.classList.remove('active'));
      // Add active class to clicked button
      this.classList.add('active');

      const filter = this.getAttribute('data-filter');

      labCards.forEach(card => {
        const status = card.getAttribute('data-status');
        const isCapstone = card.classList.contains('capstone');
        
        if (filter === 'all') {
          card.style.display = 'block';
        } else if (filter === 'capstone' && isCapstone) {
          card.style.display = 'block';
        } else if (filter === status) {
          card.style.display = 'block';
        } else {
          card.style.display = 'none';
        }
      });
    });
  });

  // Module Card Click Handler
  const moduleCards = document.querySelectorAll('.module-card');
  moduleCards.forEach(card => {
    card.addEventListener('click', function() {
      if (!this.classList.contains('locked')) {
        const module = this.getAttribute('data-module');
        window.location.href = `modules.html#module-${module}`;
      }
    });
  });

  // Smooth Scroll for Module Links
  const moduleLinks = document.querySelectorAll('a[href^="#module-"]');
  moduleLinks.forEach(link => {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      const targetId = this.getAttribute('href').substring(1);
      const targetElement = document.getElementById(targetId);
      if (targetElement) {
        targetElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  // Progress Animation
  const progressBars = document.querySelectorAll('.progress-fill');
  const observerOptions = {
    threshold: 0.5,
    rootMargin: '0px'
  };

  const progressObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const width = entry.target.style.width;
        entry.target.style.width = '0%';
        setTimeout(() => {
          entry.target.style.width = width;
        }, 100);
        progressObserver.unobserve(entry.target);
      }
    });
  }, observerOptions);

  progressBars.forEach(bar => {
    progressObserver.observe(bar);
  });

  // Module Detail Card Interactions
  const moduleDetailCards = document.querySelectorAll('.module-detail-card');
  moduleDetailCards.forEach(card => {
    if (!card.classList.contains('locked')) {
      card.style.cursor = 'pointer';
      card.addEventListener('click', function() {
        const module = this.getAttribute('data-module');
        window.location.href = `lab.html?module=${module}`;
      });
    }
  });

  // Add loading animation
  window.addEventListener('load', function() {
    document.body.style.opacity = '0';
    setTimeout(() => {
      document.body.style.transition = 'opacity 0.3s ease';
      document.body.style.opacity = '1';
    }, 100);
  });

  // Lab tutorial page - load specific lab based on URL parameter
  if (window.location.pathname.includes('lab-tutorial.html')) {
    const urlParams = new URLSearchParams(window.location.search);
    const labId = urlParams.get('lab');
    
    if (labId) {
      // Load lab-specific content
      // This would typically fetch from a data file or API
      console.log('Loading lab:', labId);
    }
  }
});

