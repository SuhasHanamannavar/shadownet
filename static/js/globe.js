// Simple 3D Value Noise for Continents
function hash(n) { return (Math.sin(n) * 43758.5453123) % 1; }
function noise3D(x, y, z) {
    let px = Math.floor(x), py = Math.floor(y), pz = Math.floor(z);
    let fx = x - px, fy = y - py, fz = z - pz;
    fx = fx*fx*(3-2*fx); fy = fy*fy*(3-2*fy); fz = fz*fz*(3-2*fz);
    let n = px + py*57 + pz*113;
    return hash(n) * (1-fx)*(1-fy)*(1-fz) + 
           hash(n+1) * fx*(1-fy)*(1-fz) +
           hash(n+57) * (1-fx)*fy*(1-fz) +
           hash(n+58) * fx*fy*(1-fz) +
           hash(n+113) * (1-fx)*(1-fy)*fz +
           hash(n+114) * fx*(1-fy)*fz +
           hash(n+170) * (1-fx)*fy*fz +
           hash(n+171) * fx*fy*fz;
}

window.AtlasGlobe = class {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    if (!this.container) return;

    this.scene = new THREE.Scene();
    // Use an orthographic-like feel or standard perspective 
    this.camera = new THREE.PerspectiveCamera(45, this.container.clientWidth / this.container.clientHeight, 0.1, 1000);
    this.camera.position.z = 3.6;
    this.camera.position.y = 0.4; // Look down slightly like the reference

    this.renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: "high-performance" });
    this.renderer.setSize(this.container.clientWidth, this.container.clientHeight);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.container.appendChild(this.renderer.domElement);

    const ambient = new THREE.AmbientLight(0xffffff, 0.2);
    this.scene.add(ambient);

    this.globeGroup = new THREE.Group();
    // Tilt the globe naturally
    this.globeGroup.rotation.x = 0.2;
    this.globeGroup.rotation.z = -0.1;
    this.scene.add(this.globeGroup);

    // Deep dark translucent core
    const coreGeo = new THREE.SphereGeometry(1.22, 48, 48);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0x050403,
      transparent: true,
      opacity: 0.9
    });
    this.core = new THREE.Mesh(coreGeo, coreMat);
    this.globeGroup.add(this.core);

    // Generate Continents using 3D Noise on a sphere
    const numDots = 4000;
    const positions = [];
    const validPoints = [];
    
    // We try many points, only keep those that fall on "land" (high noise)
    for (let i = 0; i < 15000; i++) {
        const phi = Math.acos(-1 + (2 * i) / 15000);
        const theta = Math.sqrt(15000 * Math.PI) * phi;
        const radius = 1.25;

        // Base coordinates
        const bx = Math.cos(theta) * Math.sin(phi);
        const by = Math.sin(theta) * Math.sin(phi);
        const bz = Math.cos(phi);
        
        // Complex noise overlay
        // 1. Base continental noise
        let val1 = noise3D(bx*2.0 + 10, by*2.0 + 10, bz*2.0 + 10);
        // 2. Detail noise
        let val2 = noise3D(bx*5.0, by*5.0, bz*5.0);
        
        let landIntensity = (val1 * 0.7) + (val2 * 0.3);

        if (landIntensity > 0.47) { // Ocean vs Land threshold
            const x = radius * bx;
            const y = radius * by;
            const z = radius * bz;
            positions.push(x, y, z);
            validPoints.push(new THREE.Vector3(x, y, z));
        }
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));

    // Glowing white/light-orange particles
    const material = new THREE.PointsMaterial({
        color: 0xffe9d6, 
        size: 0.015,
        transparent: true,
        opacity: 0.8,
        blending: THREE.AdditiveBlending
    });

    this.points = new THREE.Points(geometry, material);
    this.globeGroup.add(this.points);

    // Connect close points to form the wireframe continents!
    const lineGeo = new THREE.BufferGeometry();
    const linePos = [];
    
    // Performance optimization: only check nearby points 
    // We'll just randomly connect nearby points to simulate the visual
    let connections = 0;
    for (let i = 0; i < validPoints.length; i++) {
        let connected = 0;
        for (let j = i + 1; j < validPoints.length && connected < 3; j++) {
            if (validPoints[i].distanceTo(validPoints[j]) < 0.12) {
                linePos.push(validPoints[i].x, validPoints[i].y, validPoints[i].z);
                linePos.push(validPoints[j].x, validPoints[j].y, validPoints[j].z);
                connected++;
                connections++;
            }
        }
    }
    
    lineGeo.setAttribute('position', new THREE.Float32BufferAttribute(linePos, 3));
    const lineMat = new THREE.LineBasicMaterial({
        color: 0xffaa66,
        transparent: true,
        opacity: 0.25,
        blending: THREE.AdditiveBlending
    });
    this.lines = new THREE.LineSegments(lineGeo, lineMat);
    this.globeGroup.add(this.lines);

    // Floating UI Snippets attached to vectors 
    this.snippetsContainer = document.createElement('div');
    this.snippetsContainer.style.position = 'absolute';
    this.snippetsContainer.style.top = '0';
    this.snippetsContainer.style.left = '0';
    this.snippetsContainer.style.width = '100%';
    this.snippetsContainer.style.height = '100%';
    this.snippetsContainer.style.pointerEvents = 'none';
    this.snippetsContainer.style.zIndex = '3';
    this.snippetsContainer.style.overflow = 'hidden';
    this.container.appendChild(this.snippetsContainer);

    const texts = [
      "00000000 58 1d 12 00 00", "00 00 00 00",
      "CPU: LCARv7", "PMLINUX 2.3.15",
      "Memory policy: ECC", "controller found",
      "0x000F72A4: SEGFAULT", "NODE 99.42%",
      "OVERRIDE_AUTH", "SYS_BOOT_SEQ",
      "NET_TRAFFIC: HIGH", "ANOMALY_DETECTED",
      "|x.. x...|", "1222.9", "1222.9", "1222.9"
    ]; // Reference has lots of 1222.9 and small hex chunks
    
    this.snippets = [];
    for (let i = 0; i < 24; i++) {
      const el = document.createElement('div');
      el.textContent = texts[Math.floor(Math.random() * texts.length)];
      el.style.position = 'absolute';
      el.style.color = Math.random() > 0.6 ? '#ffffff' : '#ffa25e';
      el.style.fontFamily = "monospace";
      el.style.fontSize = Math.random() > 0.5 ? '9px' : '12px';
      el.style.whiteSpace = 'nowrap';
      el.style.opacity = '0';
      el.style.transition = 'opacity 0.3s ease';
      el.style.textShadow = '0 0 5px rgba(255, 255, 255, 0.4)';
      this.snippetsContainer.appendChild(el);

      const lat = Math.random() * 180 - 90;
      const lng = Math.random() * 360 - 180;
      // High orbiting distance
      const orbitalRadius = 1.35 + Math.random() * 0.4;
      const speed = 0.003 + Math.random() * 0.007;

      this.snippets.push({ el, lat, lng, speed, radius: orbitalRadius, active: false });
    }

    this.markers = [];
    window.addEventListener('resize', this.onResize.bind(this));
    this.animate();
    this.spawnSnippets();
  }

  addMarker(lat, lng, colorStr) {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lng + 180) * (Math.PI / 180);
    const r = 1.25;
    const x = -(r * Math.sin(phi) * Math.cos(theta));
    const y = r * Math.cos(phi);
    const z = r * Math.sin(phi) * Math.sin(theta);

    const geo = new THREE.SphereGeometry(0.015, 8, 8);
    const mat = new THREE.MeshBasicMaterial({ color: new THREE.Color(colorStr) });
    const mesh = new THREE.Mesh(geo, mat);
    mesh.position.set(x, y, z);
    this.globeGroup.add(mesh);

    const ringGeo = new THREE.RingGeometry(0.02, 0.03, 16);
    const ringMat = new THREE.MeshBasicMaterial({ color: new THREE.Color(colorStr), transparent:true, side: THREE.DoubleSide });
    const ring = new THREE.Mesh(ringGeo, ringMat);
    ring.position.set(x,y,z);
    ring.lookAt(new THREE.Vector3(0,0,0));
    this.globeGroup.add(ring);

    this.markers.push({ mesh, ring, time: 0 });
  }

  onResize() {
    if (!this.container) return;
    this.camera.aspect = this.container.clientWidth / this.container.clientHeight;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(this.container.clientWidth, this.container.clientHeight);
  }

  spawnSnippets() {
    setInterval(() => {
      const inactive = this.snippets.filter(s => !s.active);
      if (inactive.length > 0 && Math.random() > 0.3) {
        const s = inactive[Math.floor(Math.random() * inactive.length)];
        s.active = true;
        s.el.style.opacity = (0.5 + Math.random() * 0.5).toString();
        s.life = 100 + Math.random() * 200;
      }
    }, 400);
  }

  animate() {
    requestAnimationFrame(this.animate.bind(this));
    
    // Slow cinematic rotation matching the reference
    this.globeGroup.rotation.y += 0.001;
    this.globeGroup.rotation.x = Math.sin(Date.now() * 0.0003) * 0.05 + 0.2;

    const halfW = this.container.clientWidth / 2;
    const halfH = this.container.clientHeight / 2;

    this.snippets.forEach(s => {
      if (s.active) {
        s.lng -= s.speed;
        const phi = (90 - s.lat) * (Math.PI / 180);
        // Correctly offset rotation so text tracks the globe visually but orbits independently
        const theta = (s.lng + 180 + (this.globeGroup.rotation.y * 180 / Math.PI)) * (Math.PI / 180);
        
        const r = s.radius;
        const x = -(r * Math.sin(phi) * Math.cos(theta));
        const y = r * Math.cos(phi);
        const z = r * Math.sin(phi) * Math.sin(theta);

        const vec = new THREE.Vector3(x, y, z);
        vec.applyAxisAngle(new THREE.Vector3(1,0,0), this.globeGroup.rotation.x);
        vec.applyAxisAngle(new THREE.Vector3(0,0,1), this.globeGroup.rotation.z);
        
        if (vec.z < 0) {
          s.el.style.opacity = '0';
        } else {
          vec.project(this.camera);
          const px = (vec.x * halfW) + halfW;
          const py = -(vec.y * halfH) + halfH;
          
          s.el.style.transform = \`translate(-50%, -50%) translate3d(\${px}px, \${py}px, 0)\`;
          
          // Draw a connecting HTML line dynamically? We could, but standard shadow is good
          
          s.life--;
          if (s.life <= 0) {
            s.el.style.opacity = '0';
            setTimeout(() => s.active = false, 500);
          }
        }
      }
    });

    this.markers.forEach(m => {
      m.time += 0.05;
      const scale = 1 + Math.sin(m.time)*0.5;
      m.ring.scale.set(scale, scale, scale);
      m.ring.material.opacity = 1 - (Math.sin(m.time)*0.5 + 0.5);
    });

    this.renderer.render(this.scene, this.camera);
  }
};
