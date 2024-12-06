import {
    CurveFactory,
    Edge,
    GeomEdge,
    GeomGraph,
    GeomNode,
    Graph,
    Node,
    Point,
    layoutGeomGraph,
} from 'https://cdn.jsdelivr.net/npm/@msagl/core@1.1.23/+esm';


let currentCPVId = null;
let autoUpdatePaused = false;
let selectedBlueprintId = null;

// Initialize blueprint selection handler
function initializeBlueprintSelection() {
    const blueprintSelect = document.getElementById("blueprint");
    if (blueprintSelect) {
        // Set initial value
        selectedBlueprintId = blueprintSelect.value;
        
        // Add change event listener
        blueprintSelect.addEventListener('change', function(e) {
            selectedBlueprintId = e.target.value;
            clearSearchResults();
            updateSearchButtonState();
            if (typeof get_blueprint_component_graph === 'function') {
                get_blueprint_component_graph(selectedBlueprintId);
            }
        });
    }
}

function clearSearchResults() {
    const cpvResultsDiv = document.getElementById("cpv-search-results");
    const cpvDetailsDiv = document.getElementById("cpv-detail-results");
    
    if (cpvResultsDiv) {
        cpvResultsDiv.innerHTML = '<div class="alert alert-info p-4 bg-blue-50 text-blue-700 rounded-md">Select a blueprint and click Search to find relevant CPVs.</div>';
    }
    
    if (cpvDetailsDiv) {
        cpvDetailsDiv.innerHTML = '';
    }
    
    currentCPVId = null;
}

function updateSearchButtonState() {
    const searchBtn = document.getElementById("search-btn");
    if (searchBtn) {
        if (selectedBlueprintId) {
            searchBtn.removeAttribute('disabled');
            searchBtn.title = 'Click to search for CPVs';
            searchBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        } else {
            searchBtn.setAttribute('disabled', 'disabled');
            searchBtn.title = 'Please select a blueprint first';
            searchBtn.classList.add('opacity-50', 'cursor-not-allowed');
        }
    }
}

function searchForCPVs() {
    if (!selectedBlueprintId) {
        console.error("No blueprint selected");
        return;
    }

    const cpvResultsDiv = document.getElementById("cpv-search-results");
    cpvResultsDiv.innerHTML = '<div class="alert alert-info">Searching CPVs...</div>';

    fetch(`/api/cpv_search?blueprint_id=${selectedBlueprintId}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                cpvResultsDiv.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                return;
            }

            const cpvs = data.cpvs;
            const table = document.createElement("table");
            table.className = "min-w-full divide-y divide-gray-200 bg-white rounded-lg shadow-sm mt-4";

            const thead = document.createElement("thead");
            thead.className = "bg-gray-50";
            thead.innerHTML = `
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">CPV ID</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">CPV Name</th>
                </tr>
            `;
            table.appendChild(thead);

            const tbody = document.createElement("tbody");
            tbody.className = "bg-white divide-y divide-gray-200";

            cpvs.forEach(cpv => {
                const row = document.createElement("tr");
                row.innerHTML = `
                    <td class="px-6 py-4 text-sm text-gray-900">${cpv.id}</td>
                    <td class="px-6 py-4 text-sm">
                        <button 
                            onclick="showCPVDetails(${cpv.id}, '${cpv.cls_name}')"
                            class="text-blue-600 hover:text-blue-900">
                            ${cpv.name}
                        </button>
                    </td>
                `;
                tbody.appendChild(row);
            });

            table.appendChild(tbody);
            cpvResultsDiv.innerHTML = '';
            cpvResultsDiv.appendChild(table);
        })
        .catch(err => {
            console.error(err);
            cpvResultsDiv.innerHTML = '<div class="alert alert-danger">Error fetching CPVs</div>';
        });
}


function toggleSection(sectionId) {
    const section = document.getElementById(sectionId);
    const bullet = document.querySelector(`.bullet-${sectionId}`);

    if (!section) {
        console.error(`Section not found: ${sectionId}`);
        return;
    }

    if (section.classList.contains('hidden')) {
        section.classList.remove('hidden');
        bullet.style.color = '#2563EB'; // Set bullet point color to blue
    } else {
        section.classList.add('hidden');
        bullet.style.color = '#6B7280'; // Set bullet point color to gray
    }
}


function showCPVDetails(cpvId, clsName) {
    const cpvDetailDiv = document.getElementById("cpv-detail-results");
    cpvDetailDiv.innerHTML = '<div class="alert alert-info">Loading CPV details...</div>';

    fetch(`/api/cpv_info?name=${clsName}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                cpvDetailDiv.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                return;
            }

            // Template for each section
            const createSection = (title, content, sectionId) => `
                <div class="border-b py-2">
                    <h4 class="font-semibold text-lg cursor-pointer" onclick="toggleSection('${sectionId}')">
                        <span class="bullet-${sectionId} text-blue-500 font-bold">&#8226;</span> ${title}
                    </h4>
                    <div id="${sectionId}" class="hidden pl-4">${content}</div>
                </div>`;

            // Format required components
            const requiredComponents = data.required_components.map((comp, index, arr) => {
                const color = index === 0 || index === arr.length - 1 ? "text-red-500 font-bold" : "";
                return `<span class="${color}">${comp}</span>`;
            }).join(" &rarr; ");

            // Format attack requirements
            const attackRequirements = data.attack_requirements
                .map(req => `<li>${req}</li>`)
                .join("");

            // Format exploit steps
            const exploitSteps = data.exploit_steps
                .map(step => `<li>${step}</li>`)
                .join("");

            // Format attack vectors
            const attackVectors = data.attack_vectors.map(vector => {
                const config = Object.entries(vector.configuration || {})
                    .map(([key, value]) => `<span class="text-blue-600 font-semibold">${key}</span>: ${value}`)
                    .join(", ");
                return `
                    <li>
                        <strong>${vector.name}</strong>
                        <ul class="list-disc pl-6">
                            <li><strong>Signal:</strong> ${vector.signal}</li>
                            <li><strong>Access Level:</strong> ${vector.access_level}</li>
                            <li><strong>Configuration:</strong> ${config || "N/A"}</li>
                        </ul>
                    </li>`;
            }).join("");

            // Combine all sections
            const detailsHTML = `
                ${createSection('Entry Component', `<p>${data.entry_component}</p>`, 'entry-component')}
                ${createSection('Exit Component', `<p>${data.exit_component}</p>`, 'exit-component')}
                ${createSection('Required Components', `<p>${requiredComponents}</p>`, 'required-components')}
                ${createSection('Attack Requirements', `<ul class="list-disc pl-6">${attackRequirements}</ul>`, 'attack-requirements')}
                ${createSection('Exploit Steps', `<ul class="list-disc pl-6">${exploitSteps}</ul>`, 'exploit-steps')}
                ${createSection('Attack Vectors', `<ul class="list-disc pl-6">${attackVectors}</ul>`, 'attack-vectors')}
                ${createSection('Vulnerabilities', `<ul class="list-disc pl-6">${data.vulnerabilities.map(vuln => `<li class="text-red-600 font-semibold">${vuln}</li>`).join("")}</ul>`, 'vulnerabilities')}
                ${createSection('References', `<ul class="list-disc pl-6">${data.reference_urls.map(url => `<li><a href="${url}" target="_blank" class="text-blue-500 underline">${url}</a></li>`).join("")}</ul>`, 'references')}
            `;

            cpvDetailDiv.innerHTML = detailsHTML;
        })
        .catch(err => {
            console.error("Error fetching CPV details:", err);
            cpvDetailDiv.innerHTML = '<div class="alert alert-danger">Error loading details</div>';
        });
}


function get_blueprint_component_graph(blueprint_id) {
    $("#blueprint_graph").empty();
    $("#blueprint_options").empty();
    $.ajax({
        url: "/api/get_blueprint",
        data: {
            "id": blueprint_id,
        },
        success: function (result) {
            if (result["error"] !== undefined) {
                console.log(result["error"]);
                return;
            }

            const data = result["component_graph"];
            const width = 1400;
            const height = 400; // Increased height for better spacing

            const svg = d3.select("#blueprint_graph")
                .append("svg")
                .attr("width", width)
                .attr("height", height);

            // Create force simulation
            const simulation = d3.forceSimulation(data.nodes)
                .force("link", d3.forceLink(data.links)
                    .id(d => d.id)
                    .distance(150)) // Increased link distance
                .force("charge", d3.forceManyBody()
                    .strength(-300)) // Increased repulsion
                .force("center", d3.forceCenter(width / 2, height / 2))
                .force("collision", d3.forceCollide().radius(50)); // Added collision detection

            // REMOVED: Original color scale
            // const color = d3.scaleOrdinal(d3.schemeCategory10);

            // Create container for graph elements with zoom capability
            const container = svg.append("g");
            
            // Add zoom behavior
            svg.call(d3.zoom()
                .extent([[0, 0], [width, height]])
                .scaleExtent([0.5, 2])
                .on("zoom", (event) => {
                    container.attr("transform", event.transform);
                }));

            // Create arrow marker for directed edges
            svg.append("defs").append("marker")
                .attr("id", "arrow")
                .attr("viewBox", "0 -5 10 10")
                .attr("refX", 20)
                .attr("refY", 0)
                .attr("markerWidth", 6)
                .attr("markerHeight", 6)
                .attr("orient", "auto")
                .append("path")
                .attr("d", "M0,-5L10,0L0,5")
                .attr("fill", "#999");

            const link = container.append("g")
                .attr("class", "links")
                .selectAll("line")
                .data(data.links)
                .enter().append("line")
                .attr("class", "link")
                .attr("stroke-width", 2)
                .attr("stroke", "#999")
                .attr("marker-end", "url(#arrow)");

            // Create node groups
            const nodeGroup = container.append("g")
                .attr("class", "nodes")
                .selectAll("g")
                .data(data.nodes)
                .enter().append("g")
                .attr("class", "node-group")
                .call(d3.drag()
                    .on("start", dragstarted)
                    .on("drag", dragged)
                    .on("end", dragended));

            // MODIFIED: Node coloring based on entry property
            const node = nodeGroup.append("circle")
                .attr("r", 20)
                .attr("fill", d => d.entry ? "#FF0000" : "#808080")  // Red for entry nodes, gray for non-entry
                .attr("stroke", "#000")
                .attr("stroke-width", 1.5);

            // ADDED: Legend for node colors
            const legend = svg.append("g")
                .attr("class", "legend")
                .attr("transform", "translate(20,20)");

            const legendItems = [
                { color: "#FF0000", label: "Entry Point" },
                { color: "#808080", label: "Regular Node" }
            ];

            legendItems.forEach((item, i) => {
                const legendRow = legend.append("g")
                    .attr("transform", `translate(0, ${i * 20})`);
                    
                legendRow.append("circle")
                    .attr("cx", 10)
                    .attr("cy", 10)
                    .attr("r", 7)
                    .attr("fill", item.color);
                    
                legendRow.append("text")
                    .attr("x", 30)
                    .attr("y", 15)
                    .text(item.label)
                    .style("font-size", "12px");
            });

            // Add labels with background
            const labels = nodeGroup.append("g")
                .attr("class", "label-group");

            // Add white background for labels
            labels.append("rect")
                .attr("class", "label-background")
                .attr("fill", "white")
                .attr("opacity", 0.8);

            // Add text labels
            const text = labels.append("text")
                .attr("dy", -30)
                .attr("text-anchor", "middle")
                .text(d => d.name)
                .each(function() {
                    const bbox = this.getBBox();
                    const parent = this.parentNode;
                    const rect = parent.querySelector("rect");
                    rect.setAttribute("x", bbox.x - 5);
                    rect.setAttribute("y", bbox.y - 2);
                    rect.setAttribute("width", bbox.width + 10);
                    rect.setAttribute("height", bbox.height + 4);
                });

            // Update positions on simulation tick
            simulation.on("tick", () => {
                link
                    .attr("x1", d => d.source.x)
                    .attr("y1", d => d.source.y)
                    .attr("x2", d => d.target.x)
                    .attr("y2", d => d.target.y);

                nodeGroup
                    .attr("transform", d => `translate(${d.x},${d.y})`);
            });

            // Drag functions
            function dragstarted(event, d) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }

            function dragged(event, d) {
                d.fx = event.x;
                d.fy = event.y;
            }

            function dragended(event, d) {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }

            // Handle blueprint options
            const blueprint_options = $("#blueprint_options");
            console.log(data.options);
            for (const [option, value] of Object.entries(data.options)) {
                const option_div = $("<div></div>").text(`${option}:`);
                const input = $("<input>");
                input.attr("type", "text");
                input.val(`${value}`);
                option_div.append(input);
                blueprint_options.append(option_div);
                input.on("change", event => {
                    console.log(input.val());
                    event.preventDefault();
                    $.post({
                        url: `/api/set_blueprint_option?id=${blueprint_id}&option=${option}`,
                        data: input.val(),
                        contentType: "application/json",
                    });
                });
            }
        }
    });
}
window.get_blueprint_component_graph = get_blueprint_component_graph;

// function get_blueprint_component_graph(blueprint_id) {
//     $("#blueprint_graph").empty();
//     $("#blueprint_options").empty();
//     $.ajax({
//         url: "/api/get_blueprint",
//         data: {
//             "id": blueprint_id,
//         },
//         success: function (result) {
//             if (result["error"] !== undefined) {
//                 console.log(result["error"]);
//                 return;
//             }

//             const data = result["component_graph"];
//             const width = 1400;
//             const height = 400; // Increased height for better spacing

//             const svg = d3.select("#blueprint_graph")
//                 .append("svg")
//                 .attr("width", width)
//                 .attr("height", height);

//             // Create force simulation
//             const simulation = d3.forceSimulation(data.nodes)
//                 .force("link", d3.forceLink(data.links)
//                     .id(d => d.id)
//                     .distance(150)) // Increased link distance
//                 .force("charge", d3.forceManyBody()
//                     .strength(-300)) // Increased repulsion
//                 .force("center", d3.forceCenter(width / 2, height / 2))
//                 .force("collision", d3.forceCollide().radius(50)); // Added collision detection

//             const color = d3.scaleOrdinal(d3.schemeCategory10);

//             // Create container for graph elements with zoom capability
//             const container = svg.append("g");
            
//             // Add zoom behavior
//             svg.call(d3.zoom()
//                 .extent([[0, 0], [width, height]])
//                 .scaleExtent([0.5, 2])
//                 .on("zoom", (event) => {
//                     container.attr("transform", event.transform);
//                 }));

//             // Create arrow marker for directed edges
//             svg.append("defs").append("marker")
//                 .attr("id", "arrow")
//                 .attr("viewBox", "0 -5 10 10")
//                 .attr("refX", 20)
//                 .attr("refY", 0)
//                 .attr("markerWidth", 6)
//                 .attr("markerHeight", 6)
//                 .attr("orient", "auto")
//                 .append("path")
//                 .attr("d", "M0,-5L10,0L0,5")
//                 .attr("fill", "#999");

//             const link = container.append("g")
//                 .attr("class", "links")
//                 .selectAll("line")
//                 .data(data.links)
//                 .enter().append("line")
//                 .attr("class", "link")
//                 .attr("stroke-width", 2)
//                 .attr("stroke", "#999")
//                 .attr("marker-end", "url(#arrow)");

//             // Create node groups
//             const nodeGroup = container.append("g")
//                 .attr("class", "nodes")
//                 .selectAll("g")
//                 .data(data.nodes)
//                 .enter().append("g")
//                 .attr("class", "node-group")
//                 .call(d3.drag()
//                     .on("start", dragstarted)
//                     .on("drag", dragged)
//                     .on("end", dragended));

//             // Add circles to node groups
//             const node = nodeGroup.append("circle")
//                 .attr("r", 20)
//                 .attr("fill", d => color(d.id));

//             // Add labels with background
//             const labels = nodeGroup.append("g")
//                 .attr("class", "label-group");

//             // Add white background for labels
//             labels.append("rect")
//                 .attr("class", "label-background")
//                 .attr("fill", "white")
//                 .attr("opacity", 0.8);

//             // Add text labels
//             const text = labels.append("text")
//                 .attr("dy", -30)
//                 .attr("text-anchor", "middle")
//                 .text(d => d.name)
//                 .each(function() {
//                     const bbox = this.getBBox();
//                     const parent = this.parentNode;
//                     const rect = parent.querySelector("rect");
//                     rect.setAttribute("x", bbox.x - 5);
//                     rect.setAttribute("y", bbox.y - 2);
//                     rect.setAttribute("width", bbox.width + 10);
//                     rect.setAttribute("height", bbox.height + 4);
//                 });

//             // Update positions on simulation tick
//             simulation.on("tick", () => {
//                 link
//                     .attr("x1", d => d.source.x)
//                     .attr("y1", d => d.source.y)
//                     .attr("x2", d => d.target.x)
//                     .attr("y2", d => d.target.y);

//                 nodeGroup
//                     .attr("transform", d => `translate(${d.x},${d.y})`);
//             });

//             // Drag functions
//             function dragstarted(event, d) {
//                 if (!event.active) simulation.alphaTarget(0.3).restart();
//                 d.fx = d.x;
//                 d.fy = d.y;
//             }

//             function dragged(event, d) {
//                 d.fx = event.x;
//                 d.fy = event.y;
//             }

//             function dragended(event, d) {
//                 if (!event.active) simulation.alphaTarget(0);
//                 d.fx = null;
//                 d.fy = null;
//             }

//             // Handle blueprint options
//             const blueprint_options = $("#blueprint_options");
//             console.log(data.options);
//             for (const [option, value] of Object.entries(data.options)) {
//                 const option_div = $("<div></div>").text(`${option}:`);
//                 const input = $("<input>");
//                 input.attr("type", "text");
//                 input.val(`${value}`);
//                 option_div.append(input);
//                 blueprint_options.append(option_div);
//                 input.on("change", event => {
//                     console.log(input.val());
//                     event.preventDefault();
//                     $.post({
//                         url: `/api/set_blueprint_option?id=${blueprint_id}&option=${option}`,
//                         data: input.val(),
//                         contentType: "application/json",
//                     });
//                 });
//             }
//         }
//     });
// }
// window.get_blueprint_component_graph = get_blueprint_component_graph;

// Initialize on document load
document.addEventListener('DOMContentLoaded', function() {
    initializeBlueprintSelection();
    updateSearchButtonState();
    clearSearchResults();
});

// Make functions available globally
window.searchForCPVs = searchForCPVs;
window.showCPVDetails = showCPVDetails;
window.toggleSection = toggleSection;