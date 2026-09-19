// =====================================
// CYBERWATCH-AI
// MARKER ENGINE
// =====================================

const cyberMarkers = [];

// Convert Latitude/Longitude
// to 3D Sphere Coordinates

function latLonToVector3(lat, lon, radius) {

    const phi =
        (90 - lat) *
        (Math.PI / 180);

    const theta =
        (lon + 180) *
        (Math.PI / 180);

    return new THREE.Vector3(

        -(radius *
        Math.sin(phi) *
        Math.cos(theta)),

        radius *
        Math.cos(phi),

        radius *
        Math.sin(phi) *
        Math.sin(theta)

    );

}


// =====================================
// Create Marker
// =====================================

function createMarker(
    latitude,
    longitude,
    color
){

    const position =
        latLonToVector3(
            latitude,
            longitude,
            4.06
        );

    // ----------------------
    // Core
    // ----------------------

    const core =
        new THREE.Mesh(

            new THREE.SphereGeometry(
                0.05,
                24,
                24
            ),

            new THREE.MeshBasicMaterial({

                color: color

            })

        );

    core.position.copy(position);

    scene.add(core);

    // ----------------------
    // Glow
    // ----------------------

    const glow =
        new THREE.Mesh(

            new THREE.SphereGeometry(
                0.11,
                24,
                24
            ),

            new THREE.MeshBasicMaterial({

                color: color,

                transparent: true,

                opacity: 0.35

            })

        );

    glow.position.copy(position);

    scene.add(glow);

    cyberMarkers.push({

        core,

        glow,

        phase:
            Math.random() *
            Math.PI * 2

    });

}