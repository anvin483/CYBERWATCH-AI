// ===================================
// EARTH CREATION
// ===================================

function createEarth(scene) {

    const loader = new THREE.TextureLoader();

    const dayTexture =
        loader.load("/static/images/earth_day.jpg");

    const bumpTexture =
        loader.load("/static/images/earth_bump.jpg");

    const specularTexture =
        loader.load("/static/images/earth_specular.jpg");

    const geometry =
        new THREE.SphereGeometry(
            4,
            128,
            128
        );

    const material =
        new THREE.MeshPhongMaterial({

            map: dayTexture,

            bumpMap: bumpTexture,

            bumpScale: 0.08,

            specularMap: specularTexture,

            specular: new THREE.Color("grey"),

            shininess: 18

        });

    const earth =
        new THREE.Mesh(
            geometry,
            material
        );

    earth.rotation.z =
        THREE.MathUtils.degToRad(23.5);

    scene.add(earth);

    return earth;

}