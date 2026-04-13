# BWF Toolkit - Unified UI Design Standard

This document defines the standard UI structure that ALL modules MUST follow for consistency.

## 🎨 **Design Principles**

1. **Fixed 280px Sidebar** - Always on the left
2. **Consistent Colors** - Dark theme with accent colors
3. **Standard Margins** - 20px padding on content
4. **Uniform Cards** - Dark gradient backgrounds
5. **Same Typography** - System fonts, consistent sizes

---

## 📐 **Standard HTML Structure**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Module X - [Name] | BWF Toolkit</title>
    <link rel="stylesheet" href="/static/unified-style.css">
    <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.js"></script>
</head>
<body>
    
    <div class="main-layout">
        <!-- SIDEBAR (COPY THIS EXACTLY) -->
        <nav class="sidebar">
            <div class="sidebar-header">
                <h2 class="sidebar-title">BWF Toolkit</h2>
                <p class="sidebar-subtitle">Wireless Security Platform</p>
            </div>
            <div class="sidebar-nav">
                <a href="/" class="sidebar-link"><i data-lucide="layout-dashboard" class="sidebar-icon"></i><span>Dashboard</span></a>
                <a href="/module1" class="sidebar-link"><i data-lucide="wifi" class="sidebar-icon"></i><span>Bluetooth & Wi-Fi Scanner</span></a>
                <a href="/module2" class="sidebar-link"><i data-lucide="alert-triangle" class="sidebar-icon"></i><span>Rogue Detection</span></a>
                <a href="/module3" class="sidebar-link"><i data-lucide="package" class="sidebar-icon"></i><span>Packet Sniffing</span></a>
                <a href="/module4" class="sidebar-link"><i data-lucide="shield-alert" class="sidebar-icon"></i><span>Attack Detection</span></a>
                <a href="/module5" class="sidebar-link"><i data-lucide="brain" class="sidebar-icon"></i><span>Anomaly Detection</span></a>
                <a href="/module6" class="sidebar-link"><i data-lucide="file-text" class="sidebar-icon"></i><span>Forensic Reporting</span></a>
                <a href="/module7" class="sidebar-link"><i data-lucide="shield-check" class="sidebar-icon"></i><span>Mitigation & Response</span></a>
                <a href="/module8" class="sidebar-link"><i data-lucide="monitor" class="sidebar-icon"></i><span>Endpoint Security</span></a>
            </div>
        </nav>

        <!-- MAIN CONTENT -->
        <div class="main-content">
            <div class="content-container">
                
                <!-- MODULE HEADER -->
                <div class="page-header [COLOR]">
                    <h1 class="page-title">🎯 Module X - [Module Name]</h1>
                    <p class="page-subtitle">[Module Description]</p>
                </div>

                <!-- STATISTICS GRID (Optional) -->
                <div class="stats-grid">
                    <div class="stat-card [COLOR]">
                        <div class="stat-value [COLOR]" id="stat1">0</div>
                        <div class="stat-label">Stat Label 1</div>
                    </div>
                    <!-- Add more stat cards as needed -->
                </div>

                <!-- CONTENT CARDS -->
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title [COLOR]">📊 Card Title</h2>
                        <button class="btn btn-primary btn-sm" onclick="refresh()">🔄 Refresh</button>
                    </div>
                    <!-- Card content here -->
                </div>

            </div>
        </div>
    </div>

    <script>
        // Initialize Lucide icons
        lucide.createIcons();
        
        // Set active sidebar link
        const currentPath = window.location.pathname;
        document.querySelectorAll('.sidebar-link').forEach(link => {
            if (link.getAttribute('href') === currentPath) {
                link.classList.add('active');
            }
        });
    </script>

</body>
</html>
```

---

## 🎨 **Color Scheme**

### Available Header Colors
- `.page-header` - Default Blue (#3b82f6)
- `.page-header.cyan` - Cyan (#06b6d4) - Use for Module 8
- `.page-header.purple` - Purple (#8b5cf6) - Use for Module 5
- `.page-header.green` - Green (#10b981) - Use for Module 2
- `.page-header.orange` - Orange (#f59e0b) - Use for Module 6
- `.page-header.red` - Red (#ef4444) - Use for Module 4

### Stat Card Colors
- `.stat-card.blue` with `.stat-value.blue`
- `.stat-card.cyan` with `.stat-value.cyan`
- `.stat-card.green` with `.stat-value.green`
- `.stat-card.purple` with `.stat-value.purple`
- `.stat-card.orange` with `.stat-value.orange`
- `.stat-card.red` with `.stat-value.red`

### Card Title Colors
- `.card-title.blue`
- `.card-title.cyan`
- `.card-title.green`
- `.card-title.purple`
- `.card-title.orange`
- `.card-title.red`

---

## 📏 **Standard Dimensions**

- **Sidebar Width**: 280px (fixed)
- **Content Padding**: 20px
- **Card Padding**: 25px
- **Border Radius**: 12px for cards, 8px for buttons
- **Gap Between Items**: 20px
- **Max Content Width**: 1900px

---

## 🔤 **Typography**

- **Page Title**: 32px, font-weight: 700
- **Page Subtitle**: 14px, opacity: 0.9
- **Card Title**: 24px, font-weight: 700
- **Stat Value**: 32px, font-weight: 700
- **Stat Label**: 13px
- **Body Text**: 14px
- **Button Text**: 13px, font-weight: 600

---

## 🎯 **Module-Specific Configurations**

### Dashboard (/)
- Header: Default Blue
- Icon: `layout-dashboard`

### Module 1 - Scanner
- Header: Default Blue
- Icon: `wifi`
- Accent Colors: Blue and Cyan

### Module 2 - Rogue Detection
- Header: Green
- Icon: `alert-triangle`
- Accent Colors: Green and Red

### Module 3 - Packet Sniffing
- Header: Default Blue
- Icon: `package`
- Accent Colors: Blue and Purple

### Module 4 - Attack Detection
- Header: Red
- Icon: `shield-alert`
- Accent Colors: Red and Orange

### Module 5 - Anomaly Detection
- Header: Purple
- Icon: `brain`
- Accent Colors: Purple and Blue

### Module 6 - Forensic Reporting
- Header: Orange
- Icon: `file-text`
- Accent Colors: Orange and Blue

### Module 7 - Mitigation & Response
- Header: Green
- Icon: `shield-check`
- Accent Colors: Green and Cyan

### Module 8 - Endpoint Security
- Header: Cyan
- Icon: `monitor`
- Accent Colors: Cyan and Blue

---

## ✅ **Checklist for Each Module**

- [ ] Uses `/static/unified-style.css`
- [ ] 280px fixed sidebar with all 9 navigation links
- [ ] Correct active state on current module
- [ ] Page header with appropriate color class
- [ ] Content padding of 20px
- [ ] Cards with 25px padding
- [ ] Consistent border radius (12px cards, 8px buttons)
- [ ] Lucide icons initialized
- [ ] Responsive behavior (sidebar collapses on mobile)

---

## 🚀 **Quick Reference: CSS Classes**

### Layout
- `.main-layout` - Main flex container
- `.sidebar` - Fixed sidebar
- `.main-content` - Content area
- `.content-container` - Max-width content wrapper

### Components
- `.page-header` - Module header
- `.stats-grid` - Statistics grid container
- `.stat-card` - Individual stat card
- `.card` - Content card
- `.btn` - Button base class
- `.table` - Table base class
- `.badge` - Badge/label base class
- `.modal` - Modal container

### Utilities
- `.text-center`, `.text-right`
- `.mb-10`, `.mb-20`, `.mb-30`
- `.mt-10`, `.mt-20`, `.mt-30`
- `.flex`, `.flex-col`
- `.gap-10`, `.gap-20`
- `.items-center`, `.justify-between`

---

This standard ensures a cohesive, professional look across the entire BWF Toolkit platform.






