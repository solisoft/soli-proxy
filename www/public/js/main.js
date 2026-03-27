// Copy code block content to clipboard
function copyCode(btn) {
    var codeBlock = btn.closest('.code-window') || btn.closest('.code-block');
    var code = codeBlock.querySelector('code') || codeBlock.querySelector('pre');
    navigator.clipboard.writeText(code.textContent).then(function() {
        var orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(function() { btn.textContent = orig; }, 2000);
    });
}

// Tab switching for multi-tab code blocks
function switchTab(group, tab) {
    // Hide all content panels in this group
    var panels = document.querySelectorAll('[data-tab-group="' + group + '"]');
    panels.forEach(function(p) { p.classList.add('hidden'); });
    // Show selected panel
    var active = document.getElementById(group + '-' + tab);
    if (active) active.classList.remove('hidden');
    // Update tab buttons
    var btns = document.querySelectorAll('[data-tab-btn="' + group + '"]');
    btns.forEach(function(b) {
        if (b.dataset.tab === tab) {
            b.className = 'px-3 py-1.5 text-xs font-medium rounded-md transition-all text-white bg-white/10 shadow-sm';
        } else {
            b.className = 'px-3 py-1.5 text-xs font-medium rounded-md transition-all text-gray-400 hover:text-white hover:bg-white/5';
        }
    });
}

// Mobile nav toggle
function toggleMobileNav() {
    document.getElementById('mobileNav').classList.toggle('open');
}

// Smooth scroll for anchor links
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            var target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
            // Close mobile nav if open
            var nav = document.getElementById('mobileNav');
            if (nav && nav.classList.contains('open')) nav.classList.remove('open');
        });
    });

    // Scroll reveal observer
    var observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
            if (entry.isIntersecting) {
                entry.target.classList.add('reveal-visible');
                observer.unobserve(entry.target);
            }
        });
    }, { root: null, rootMargin: '0px', threshold: 0.1 });

    document.querySelectorAll('.reveal-on-scroll').forEach(function(el) {
        observer.observe(el);
    });
});
