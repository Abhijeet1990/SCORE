using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SwagShopLibrary.MarkovDecisionProcess;

namespace SwagShopLibrary
{
    public class CyberPhysicalMDP_5bus
    {
        public class trans_prob
        {
            public double prob;
            public int next_state;
            public double reward;
            public bool done;
            public trans_prob(double _prob, int _ns, double _r, bool _done)
            {
                prob = _prob;
                next_state = _ns;
                reward = _r;
                done = _done;
            }
        }
        public class vulnerability
        {
            public string vuln_name;
            public double score;
            public bool isExploited;
            public bool isPatched;
        }
        public class host
        {
            public string hostId;
            public List<vulnerability> vulns = new List<vulnerability>();
            public List<host> neighbors = new List<host>();
        }
        public static int valueItrCount = 0;
        public static int policyItrCount = 0;

        public class cyberPhysicalState
        {
            public int ID;
            public List<host> exploits = new List<host>(); // it is the list of the host it has privilege over. 
            public List<cyberPhysicalState> neighbors = new List<cyberPhysicalState>(); // It represents each neighboring mdp state.
            public int layer;
            public List<int> possibleActions = new List<int>();
            //public double performance_index; // for each state 
            //public double security_index; // mdp value function (needs to be computed; value iteration)
        }
        public enum Action { NoAction = 1, changeFWRule, patchVuln, switchToManual, phyAction };

        // State Space creation
        /*
         Optimal policy for different states
             */
        //public int[] optimalAct = { 1, 3, 3, 3, 3, 3, 3, 2, 3, 2, 2, 4, 4, 4, 5, 5, 5 };

        public List<cyberPhysicalState> createMDPStates()
        {
            // for example we have 8 host.. currently the list of host are taken for testing purpose hence they are hardcoded.
            List<host> hosts = new List<host>();
            hosts.Add(new host { hostId = "H1A", vulns = new List<vulnerability> { new vulnerability { vuln_name = "v1", score = 4.567, isExploited = false, isPatched = true } } });
            hosts.Add(new host { hostId = "H2A", vulns = new List<vulnerability> { new vulnerability { vuln_name = "v2", score = 8.767, isExploited = false, isPatched = true } } });
            hosts.Add(new host { hostId = "RA", vulns = new List<vulnerability>() });
            hosts.Add(new host { hostId = "H1B", vulns = new List<vulnerability> { new vulnerability { vuln_name = "v3", score = 5.467, isExploited = false, isPatched = true }, new vulnerability { vuln_name = "v2", score = 8.767, isExploited = false, isPatched = true } } });
            hosts.Add(new host { hostId = "H2B", vulns = new List<vulnerability> { new vulnerability { vuln_name = "v1", score = 4.567, isExploited = false, isPatched = true } } });
            hosts.Add(new host { hostId = "RB", vulns = new List<vulnerability>() });
            hosts.Add(new host { hostId = "H1C", vulns = new List<vulnerability> { new vulnerability { vuln_name = "v4", score = 2.567, isExploited = false, isPatched = true } } });
            hosts.Add(new host { hostId = "RC", vulns = new List<vulnerability>() });
            hosts.Add(new host { hostId = "H1D", vulns = new List<vulnerability> { new vulnerability { vuln_name = "v1", score = 4.567, isExploited = false, isPatched = true } } });
            hosts.Add(new host { hostId = "H2D", vulns = new List<vulnerability> { new vulnerability { vuln_name = "v2", score = 8.767, isExploited = false, isPatched = true } } });
            hosts.Add(new host { hostId = "RD", vulns = new List<vulnerability>() });
            hosts.Add(new host { hostId = "H1E", vulns = new List<vulnerability> { new vulnerability { vuln_name = "v3", score = 5.467, isExploited = false, isPatched = true }, new vulnerability { vuln_name = "v2", score = 8.767, isExploited = false, isPatched = true } } });
            hosts.Add(new host { hostId = "H2E", vulns = new List<vulnerability> { new vulnerability { vuln_name = "v1", score = 4.567, isExploited = false, isPatched = true } } });
            hosts.Add(new host { hostId = "RE", vulns = new List<vulnerability>() });

            // List of attackpaths
            List<string> attackPaths = new List<string> { "H1A(v1):H2A(v2):RA", "H2A(v2):RA", "H1B(v3):H2B(v1):RB", "H2B(v1):RB", "H1B(v2):RB", "H1C(v4):RC" , "H1D(v1):H2D(v2):RD", "H2D(v2):RD", "H1E(v3):H2E(v1):RE", "H2E(v1):RE", "H1E(v2):RE" };

            // for time being lets consider all are neighbor to each other in a given substation
            for (int i = 0; i < attackPaths.Count; i++)
            {
                var elements = attackPaths[i].Split(':');
                for (int j = 0; j < elements.Length - 1; j++)
                {
                    host h = hosts.Single(a => a.hostId == elements[j].Split('(')[0]);
                    host neigh = hosts.Single(a => a.hostId == elements[j + 1].Split('(')[0]);
                    if (!h.neighbors.Contains(neigh))
                        h.neighbors.Add(neigh);
                }
            }

            // After the neighbors are formed create cyber states where Phy Normal
            List<cyberPhysicalState> states = new List<cyberPhysicalState>();
            var normal = new cyberPhysicalState { ID = 0, exploits = new List<host>(), layer = 0 };
            states.Add(normal);

            int stateCount = 1;
            // Layer 1 states
            for (int i = 0; i < hosts.Count; i++)
            {
                if (hosts[i].neighbors.Count != 0)
                {
                    // get the list of exploits possible 
                    var c = new cyberPhysicalState { ID = stateCount++, exploits = new List<host> { hosts[i] }, layer = 1 };
                    normal.neighbors.Add(c); // downward link
                    c.neighbors.Add(normal); // upward link
                    // Add the state if doesnt exist
                    states.Add(c);
                }
            }

            // Layer 2 states
            var firstLayercount = states.Count;
            for (int i = 1; i < firstLayercount; i++) // excluding the first normal state
            {
                for (int j = 0; j < states[i].exploits.Count; j++)
                {
                    var x = states[i].exploits[j];
                    foreach (var item in x.neighbors)
                    {
                        if (item.neighbors.Count != 0)
                        {
                            var c = new cyberPhysicalState { ID = stateCount++, exploits = new List<host> { x, item }, layer = 2 };
                            states[i].neighbors.Add(c); // downward link
                            c.neighbors.Add(states[i]); // upward link
                            states.Add(c);
                        }
                        else // Layer 3 states .. all the Relays compromised
                        {
                            var c = new cyberPhysicalState { ID = stateCount++, exploits = new List<host> { item }, layer = 3 };
                            if (!checkIfExist(states, c))
                            {
                                states[i].neighbors.Add(c); // downward link
                                c.neighbors.Add(states[i]); // upward link
                                states.Add(c);
                            }
                            else
                            {
                                stateCount--;
                            }
                        }
                    }
                }
            }

            // Add the links for the newly added states in Layer 2 and Layer 3
            /*
            for (int i = firstLayercount; i < states.Count; i++)
            {
                if(states[i].exploits.Count>1 && states[i].layer == 2)
                {
                    states[i].neighbors.Add(states[i + 1]); // since all the Layer 3 states are placed after the Layer 2 states hence this logic works, need to change later
                }
            }
            */
            // 

            // Add the power system states to the cyber states
            // There are 2*no_of_Relays =  breakers that could be opened by the relays .. for all the layer 3 states add the possible power system states possible

            // breaker openings are related to the transmission lines connectivity.. 
            Dictionary<string, List<string>> relay_tx = new Dictionary<string, List<string>>();
            List<string> relays = new List<string> { "RA", "RB", "RC","RD","RE" };
            relay_tx["RA"] = new List<string> { "L1", "L2" };
            relay_tx["RB"] = new List<string> { "L1", "L3" };
            relay_tx["RC"] = new List<string> { "L2", "L4" };
            relay_tx["RD"] = new List<string> { "L3" ,"L4","L5"};
            relay_tx["RE"] = new List<string> { "L5" };

            // state count from cyber side
            int cyberstatesCount = states.Count;

            List<string> checker = new List<string>();
            for (int m = 0; m < cyberstatesCount; m++)
            {
                if (states[m].layer == 3) // relays
                {
                    List<host> hs = states[m].exploits;
                    foreach (var h in hs)
                    {
                        if (relays.Contains(h.hostId))
                        {
                            var g = relay_tx[h.hostId];
                            for (int i = 0; i < g.Count; i++)
                            {
                                if (checker.Contains(g[i])) continue;
                                var cyberInduced_breakerOpen = new cyberPhysicalState { ID = stateCount++, exploits = new List<host> { new host { hostId = g[i] } }, layer = 100 }; // assign a very high layer to physical states                              
                                states[states.IndexOf(states[m])].neighbors.Add(cyberInduced_breakerOpen); // downward
                                cyberInduced_breakerOpen.neighbors.Add(states[states.IndexOf(states[m])]); // upward
                                states.Add(cyberInduced_breakerOpen);
                                checker.Add(g[i]);
                            }
                        }
                    }
                }
            }

            // Add physical states after switch to manual and add them as the neighbors of the compromised normal states
            List<cyberPhysicalState> manualEmergencyStates = new List<cyberPhysicalState>();
            foreach (var s in states)
            {
                if (s.layer == 100)
                {
                    var cyberIsolatedBreakerOpen = new cyberPhysicalState { ID = stateCount++, layer = 101 };
                    s.neighbors.Add(cyberIsolatedBreakerOpen); // add cyber compromised normal to manual state
                    cyberIsolatedBreakerOpen.neighbors.Add(states[0]); // add manual state connectivity normal state
                    states[0].neighbors.Add(cyberIsolatedBreakerOpen); // add normal state connectivity to uncompromised fault state
                    manualEmergencyStates.Add(cyberIsolatedBreakerOpen);
                }
            }
            foreach (var item in manualEmergencyStates)
            {
                states.Add(item);
            }

            //foreach (var s in states)
            //{
            //    if (s.layer == 100)
            //    {
            //        s.neighbors.Add(states[0]); // all normal state, temporarily 
            //    }
            //}
            //return states;
            return states;
        }

        public bool checkIfExist(List<cyberPhysicalState> states, cyberPhysicalState c)
        {
            var status = false;
            foreach (var item in states)
            {
                var x = item.exploits.FirstOrDefault();
                var y = c.exploits.FirstOrDefault();
                if (x == y) return true;
            }
            return status;
        }

        // Action Space creation
        public void createMDPActions(ref List<cyberPhysicalState> states)
        {

            foreach (var state in states)
            {
                switch (state.layer)
                {
                    // actions space will be layer dependent Layer 0 : everything normal => optimal action must be no action 
                    case 0:
                        state.possibleActions.Add(Convert.ToInt32(Action.NoAction));
                        continue;
                    // For Layer 1 MDP states, actions space will be => fix vulnerability patch
                    case 1:
                        state.possibleActions.Add(Convert.ToInt32(Action.NoAction));
                        state.possibleActions.Add(Convert.ToInt32(Action.patchVuln));// algorithms will be written to determine optimal patch to fix
                        continue;
                    // For Layer 2 MDP states, actions space will be => fix firewall as well vulnerability patch
                    case 2:
                        state.possibleActions.Add(Convert.ToInt32(Action.NoAction));
                        state.possibleActions.Add(Convert.ToInt32(Action.patchVuln)); // algorithms will be written to determine optimal patch to fix
                        state.possibleActions.Add(Convert.ToInt32(Action.changeFWRule));// algorithms will be written to find the optimal firewall rule to modify
                        continue;
                    // For Layer 3 MDP states, action space will be => take relays to manual, fix firewall, vulnerability patch
                    case 3:
                        state.possibleActions.Add(Convert.ToInt32(Action.NoAction));
                        state.possibleActions.Add(Convert.ToInt32(Action.patchVuln)); // algorithms will be written to determine optimal patch to fix
                        state.possibleActions.Add(Convert.ToInt32(Action.changeFWRule));// algorithms will be written to find the optimal firewall rule to modify
                        state.possibleActions.Add(Convert.ToInt32(Action.switchToManual));
                        continue;
                    // For Layer 100 MDP states, action space will be => close breaker manually, fix firewall, vulnerability patch
                    case 100:
                        state.possibleActions.Add(Convert.ToInt32(Action.NoAction));
                        state.possibleActions.Add(Convert.ToInt32(Action.patchVuln)); // algorithms will be written to determine optimal patch to fix
                        state.possibleActions.Add(Convert.ToInt32(Action.changeFWRule)); // algorithms will be written to find the optimal firewall rule to modify
                        state.possibleActions.Add(Convert.ToInt32(Action.phyAction)); // algorithms will be written to find the optimal physical actions
                        state.possibleActions.Add(Convert.ToInt32(Action.switchToManual));
                        continue;
                    case 101:
                        state.possibleActions.Add(Convert.ToInt32(Action.NoAction));
                        state.possibleActions.Add(Convert.ToInt32(Action.phyAction));
                        continue;
                    default:
                        state.possibleActions.Add(Convert.ToInt32(Action.NoAction));
                        continue;
                }
            }
        }

        // Create Reward Function for every action.. Ra(s,s') : immediate reward received after transitioning from state s to s', due to action a
        public Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> createReward(List<cyberPhysicalState> states)
        {
            Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> rewardFunctions = new Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>>();
            var actions = Enum.GetValues(typeof(Action)).Cast<Action>().ToList();

            for (int i = 0; i < actions.Count; i++)
            {
                Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double> reward = new Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>();

                foreach (var state in states)
                {
                    if (state.possibleActions.Contains(Convert.ToInt32(actions[i]))) // if the state contains the action
                    {

                        // with some probability it may stay in its own state or may transition to other neighboring state
                        Pair<cyberPhysicalState, cyberPhysicalState> sameStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = state };

                        double selfReward = 0.0;
                        if (!reward.ContainsKey(sameStateTrans)) reward.Add(sameStateTrans, selfReward);

                        Random tempReward = new Random(); // Now considering the random rewards. Further will work on creating Logical rewards. 
                        double frac = 1.0;
                        // Here instead of allocating random reward... currently give 0 reward for all actions except physical action
                        // For physical action in the Layer 100, give a reward obtained from the physical side..
                        foreach (var neighbor in state.neighbors)
                        {
                            //double r = tempReward.Next(100, 500) * tempReward.NextDouble();
                            Pair<cyberPhysicalState, cyberPhysicalState> diffStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = neighbor };
                            if (!reward.ContainsKey(diffStateTrans))
                            {

                                if (state.layer == 101 && Convert.ToInt32(actions[i]) == 5 && neighbor.layer == 0)
                                {
                                    reward.Add(diffStateTrans, 2000);
                                    //reward.Add(diffStateTrans, 20);
                                }
                                // If physical action and current state is phy compromised and next state is phy normal
                                else if (state.layer == 100)
                                {
                                    if (Convert.ToInt32(actions[i]) == 4 && neighbor.layer == 101)
                                    {
                                        //reward.Add(diffStateTrans, tempReward.Next(2500, 3000));
                                        reward.Add(diffStateTrans, tempReward.Next(2500, 3000)* GetRandomNumber(0, frac));
                                    }
                                    else // no reward for any other actions...and the agent stays in that state
                                    {
                                        reward.Add(diffStateTrans, 0);
                                    }
                                }
                                else if (state.layer == 3 && Convert.ToInt32(actions[i]) == 2 && neighbor.layer == 2)
                                {
                                    //reward.Add(diffStateTrans, tempReward.Next(80, 100));
                                    //*GetRandomNumber(0,0.1)
                                    reward.Add(diffStateTrans, tempReward.Next(80,100) * GetRandomNumber(0, frac));
                                }
                                else if (state.layer == 3 && Convert.ToInt32(actions[i]) == 3 && neighbor.layer == 2)
                                {
                                    //reward.Add(diffStateTrans, tempReward.Next(15, 20));
                                    reward.Add(diffStateTrans, tempReward.Next(15,20) * GetRandomNumber(0, frac));
                                }
                                else if (state.layer == 2 && Convert.ToInt32(actions[i]) == 2 && neighbor.layer == 1)
                                {
                                    //reward.Add(diffStateTrans, tempReward.Next(900, 1000));
                                    reward.Add(diffStateTrans, tempReward.Next(900,1000) * GetRandomNumber(0, frac));
                                }
                                else if (state.layer == 2 && Convert.ToInt32(actions[i]) == 3 && neighbor.layer == 1)
                                {
                                    //reward.Add(diffStateTrans, tempReward.Next(160, 200));
                                    reward.Add(diffStateTrans, tempReward.Next(160,200) * GetRandomNumber(0, frac));
                                }
                                else if (state.layer == 1 && Convert.ToInt32(actions[i]) == 3 && neighbor.layer == 0)
                                {
                                    //reward.Add(diffStateTrans, tempReward.Next(1800, 2000));
                                    reward.Add(diffStateTrans, tempReward.Next(1800,2000) * GetRandomNumber(0, frac));
                                }
                                else
                                { reward.Add(diffStateTrans, 0); }
                                //reward.Add(diffStateTrans, r);
                            }
                        }
                    }
                }
                rewardFunctions.Add(Convert.ToInt32(actions[i]), reward);
            }
            return rewardFunctions;
        }


        public Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> createTransitionProbability(List<cyberPhysicalState> states)
        {
            Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> transPFunctions = new Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>>();
            var actions = Enum.GetValues(typeof(Action)).Cast<Action>().ToList();

            for (int i = 0; i < actions.Count; i++)
            {
                Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double> prob = new Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>();
                foreach (var state in states)
                {
                    // the stochastic probabilities are only for the states that are cyber based....
                    // in our case we have the Layer 1, 2 and 3 has the cyber states.. state 0 and 100 are physical
                    if (state.layer == 1 || state.layer == 2 || state.layer == 3)
                    {
                        if (state.possibleActions.Contains(Convert.ToInt32(actions[i]))) // if the state contains the action
                        {

                            // with some probability it may stay in its own state or may transition to other neighboring state
                            Pair<cyberPhysicalState, cyberPhysicalState> sameStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = state };
                            Random rn = new Random();
                            //double selfProb = 0.5;
                            //double selfProb = rn.NextDouble();
                            double selfProb = GetRandomNumber(0.0, 0.3);
                            if (!prob.ContainsKey(sameStateTrans)) prob.Add(sameStateTrans, selfProb);

                            double allocateRemaining = 1.0 - selfProb;
                            int neighbor_count = state.neighbors.Count;
                            double assignProb = allocateRemaining / neighbor_count;
                            foreach (var neighbor in state.neighbors)
                            {
                                Pair<cyberPhysicalState, cyberPhysicalState> diffStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = neighbor };
                                if (!prob.ContainsKey(diffStateTrans)) prob.Add(diffStateTrans, assignProb);
                            }
                        }
                    }
                    else if (state.layer == 100) // physically compromised state
                    {
                        if (state.possibleActions.Contains(Convert.ToInt32(actions[i])))
                        {
                            if (Convert.ToInt32(actions[i]) != 4)
                            {
                                Pair<cyberPhysicalState, cyberPhysicalState> sameStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = state };
                                if (!prob.ContainsKey(sameStateTrans)) prob.Add(sameStateTrans, 1.0);
                                foreach (var neighbor in state.neighbors)
                                {
                                    Pair<cyberPhysicalState, cyberPhysicalState> diffStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = neighbor };
                                    if (!prob.ContainsKey(diffStateTrans)) prob.Add(diffStateTrans, 0.0);
                                }
                            }
                            else
                            {
                                Pair<cyberPhysicalState, cyberPhysicalState> sameStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = state };
                                if (!prob.ContainsKey(sameStateTrans)) prob.Add(sameStateTrans, 0.0);
                                foreach (var neighbor in state.neighbors)
                                {
                                    Pair<cyberPhysicalState, cyberPhysicalState> diffStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = neighbor };
                                    if (neighbor.layer == 101)
                                    {
                                        if (!prob.ContainsKey(diffStateTrans)) prob.Add(diffStateTrans, 1.0);
                                    }
                                    else
                                    {
                                        if (!prob.ContainsKey(diffStateTrans)) prob.Add(diffStateTrans, 0.0);
                                    }
                                }
                            }
                        }
                    }
                    else if (state.layer == 101) // physically compromised state
                    {
                        if (state.possibleActions.Contains(Convert.ToInt32(actions[i])))
                        {
                            if (Convert.ToInt32(actions[i]) != 5)
                            {
                                Pair<cyberPhysicalState, cyberPhysicalState> sameStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = state };
                                if (!prob.ContainsKey(sameStateTrans)) prob.Add(sameStateTrans, 1.0);
                                foreach (var neighbor in state.neighbors)
                                {
                                    Pair<cyberPhysicalState, cyberPhysicalState> diffStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = neighbor };
                                    if (!prob.ContainsKey(diffStateTrans)) prob.Add(diffStateTrans, 0.0);
                                }
                            }
                            else
                            {
                                Pair<cyberPhysicalState, cyberPhysicalState> sameStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = state };
                                if (!prob.ContainsKey(sameStateTrans)) prob.Add(sameStateTrans, 0.0);
                                foreach (var neighbor in state.neighbors)
                                {
                                    Pair<cyberPhysicalState, cyberPhysicalState> diffStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = neighbor };
                                    if (neighbor.layer == 0)
                                    {
                                        if (!prob.ContainsKey(diffStateTrans)) prob.Add(diffStateTrans, 1.0);
                                    }
                                    else
                                    {
                                        if (!prob.ContainsKey(diffStateTrans)) prob.Add(diffStateTrans, 0.0);
                                    }
                                }
                            }
                        }
                    }
                    else // current state is normal
                    {
                        Pair<cyberPhysicalState, cyberPhysicalState> sameStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = state };
                        if (!prob.ContainsKey(sameStateTrans)) prob.Add(sameStateTrans, 1.0);
                        foreach (var neighbor in state.neighbors)
                        {
                            Pair<cyberPhysicalState, cyberPhysicalState> diffStateTrans = new Pair<cyberPhysicalState, cyberPhysicalState> { First = state, Second = neighbor };
                            if (!prob.ContainsKey(diffStateTrans)) prob.Add(diffStateTrans, 0.0);
                        }
                    }
                }
                transPFunctions.Add(Convert.ToInt32(actions[i]), prob);
            }
            return transPFunctions;
        }

        public double GetRandomNumber(double minimum, double maximum)
        {
            Random random = new Random();
            return random.NextDouble() * (maximum - minimum) + minimum;
        }

        public double ValueIteration(List<cyberPhysicalState> mdpStates, Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> P, Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> R, double gamma)
        {
            // Value Iteration
            double[] V = new double[mdpStates.Count];
            V = valueItrn(mdpStates, P, R, gamma, V);

            // After V is obtained, extract policy
            int[] policy = new int[mdpStates.Count];
            policy = extractPolicy(mdpStates, P, R, gamma, V, policy);

            int accuracy = 0;
            // Compute Accuracy for Value Iteration
            //for (int i = 0; i < policy.Length; i++)
            //{
            //    if (policy[i] == optimalAct[i])
            //    {
            //        accuracy += 1;
            //    }
            //}
            //double accuracyPercent = (double)accuracy / mdpStates.Count;
            //Console.WriteLine("Accuracy of the result value iteration: {0}", accuracyPercent);

            // Run the policy for a number of episodes
            int numEpisodes = 10000;
            double score = 0;
            for (int i = 0; i < numEpisodes; i++)
            {
                score += runEpisode(mdpStates, R, gamma, policy);
            }
            //Console.WriteLine("The optimal reward using Value Iteration is {0}", Convert.ToDouble(score / numEpisodes));
            return Convert.ToDouble(score / numEpisodes);
        }
        public double[] valueItrn(List<cyberPhysicalState> states, Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> probT, Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> reward, double disFactor, double[] V)
        {
            int max_itr = 10000;
            double eps = 0.000001;
            double[] prev_V = new double[states.Count];
            for (int i = 0; i < max_itr; i++)
            {
                for (int g = 0; g < states.Count; g++)
                {
                    prev_V[g] = V[g];
                }
                double diff = 0;
                for (int s = 0; s < states.Count; s++)
                {
                    var possibleActions = states[s].possibleActions;
                    double[] q_sa = new double[possibleActions.Count];
                    int c = 0;
                    //double estimatedReward = 0;
                    for (int k = 0; k < possibleActions.Count; k++)
                    {
                        var transProb = probT[possibleActions[k]];
                        var rew = reward[possibleActions[k]];
                        double gamma_summation_expression = 0;
                        double immed_reward = 0;
                        foreach (var item in transProb)
                        {
                            if (item.Key.First == states[s])
                            {
                                foreach (var r in rew)
                                {
                                    if (r.Key.First == item.Key.First && r.Key.Second == item.Key.Second)
                                    {
                                        immed_reward = rew[r.Key];
                                    }
                                }
                                var pair = item.Key;
                                var prob = item.Value;

                                //estimatedReward += immed_reward;
                                gamma_summation_expression += disFactor * prob * prev_V[states.FindIndex(a => a.ID == pair.Second.ID)];
                            }
                        }
                        //estimatedReward = estimatedReward / transProb.Count; // Estimated Reward

                        //q_sa[c] = estimatedReward + gamma_summation_expression; 
                        q_sa[c] = immed_reward + gamma_summation_expression;// check the algorithm 4 of smartgridcomm paper
                        c += 1;
                    }
                    V[s] = q_sa.Max();
                    diff += Math.Abs(prev_V[s] - V[s]);
                }
                if (diff <= eps)
                {
                    Console.WriteLine("Value iteration converged in {0} steps.", i);
                    valueItrCount += i;
                    break;
                }
            }
            return V;
        }
        // Extract policy
        public int[] extractPolicy(List<cyberPhysicalState> states, Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> P, Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> R, double gamma, double[] V, int[] policy)
        {
            for (int i = 0; i < states.Count; i++)
            {
                double[] q_sa = new double[states[i].possibleActions.Count];
                for (int j = 0; j < states[i].possibleActions.Count; j++)
                {
                    var transProb = P[states[i].possibleActions[j]];
                    var rew = R[states[i].possibleActions[j]];
                    double immed_reward = 0;
                    foreach (var item in transProb)
                    {
                        if (item.Key.First == states[i])
                        {
                            foreach (var r in rew)
                            {
                                if (r.Key.First == item.Key.First && r.Key.Second == item.Key.Second)
                                {
                                    immed_reward = rew[r.Key];
                                }
                            }
                            var pair = item.Key;
                            var prob = item.Value;
                            q_sa[j] += (immed_reward + prob * gamma * V[states.FindIndex(a => a.ID == pair.Second.ID)]);
                        }
                    }
                }
                var optimalQ = q_sa.Max();
                policy[i] = states[i].possibleActions[q_sa.ToList().IndexOf(optimalQ)];
            }
            return policy;
        }
        // Run the policy for a given episode
        public double runEpisode(List<cyberPhysicalState> states, Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> R, double gamma, int[] policy)
        {
            Random rn = new Random();
            int startState = rn.Next(0, states.Count);
            //int startState = 13;
            double tot_rew = 0.0;
            int step_idx = 0;
            int currState = startState; int nextState = 0;
            while (true)
            {
                var rew = R[policy[currState]];
                Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double> temp = new Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>();
                foreach (var item in rew)
                {
                    if (item.Key.First.ID == currState)
                    {
                        temp.Add(item.Key, item.Value);
                    }
                }
                // get the maximum rewarding state transition for that state change
                var max = temp.Aggregate((l, r) => l.Value > r.Value ? l : r).Key;

                tot_rew += Math.Pow(gamma, step_idx) * rew[max];
                nextState = max.Second.ID;
                step_idx += 1;
                if (currState == 0) break; // cyber and physical normal = > break, basically that is the goal state
                currState = nextState;
            }
            return tot_rew;
        }

        public double PolicyIteration(List<cyberPhysicalState> mdpStates, Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> P, Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> R, double gamma)
        {
            int nS = mdpStates.Count;
            int[] policy = new int[nS];
            Random rn = new Random();
            for (int i = 0; i < nS; i++)
            {
                var rndActionIndex = rn.Next(mdpStates[i].possibleActions.Count);
                policy[i] = mdpStates[i].possibleActions[rndActionIndex];
            }
            int maxItr = 200000;
            for (int j = 0; j < maxItr; j++)
            {
                var oldPolicyV = computePolicy(mdpStates, P, R, gamma, policy);
                int[] newPolicy = new int[nS];
                newPolicy = extractPolicy(mdpStates, P, R, gamma, oldPolicyV, newPolicy);
                if (checkEquality(policy, newPolicy))
                {
                    Console.WriteLine("Policy iteration converged in {0} steps", j);
                    policyItrCount += j;
                    break;
                }
                for (int m = 0; m < nS; m++)
                {
                    policy[m] = newPolicy[m];
                }
            }
            int accuracy = 0;
            // Compute Accuracy for Value Iteration
            //for (int i = 0; i < policy.Length; i++)
            //{
            //    if (policy[i] == optimalAct[i])
            //    {
            //        accuracy += 1;
            //    }
            //}
            double accuracyPercent = (double)accuracy / mdpStates.Count;
            //Console.WriteLine("Accuracy of the result policy iteration: {0}", accuracyPercent);

            // Run the policy for a number of episodes
            int numEpisodes = 10000;
            double score = 0;
            for (int i = 0; i < numEpisodes; i++)
            {
                score += runEpisode(mdpStates, R, gamma, policy);
            }
            //Console.WriteLine("The optimal reward using Policy Iteration is {0}", Convert.ToDouble(score / numEpisodes));
            return Convert.ToDouble(score / numEpisodes);
        }

        public bool checkEquality(int[] origA, int[] newA)
        {
            for (int i = 0; i < origA.Count(); i++)
            {
                if (origA[i] != newA[i]) return false;
            }
            return true;
        }
        public double[] computePolicy(List<cyberPhysicalState> states, Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> P, Dictionary<int, Dictionary<Pair<cyberPhysicalState, cyberPhysicalState>, double>> R, double gamma, int[] policy)
        {
            int nS = states.Count;
            double[] V = new double[nS];
            double eps = 0.1;
            while (true)
            {
                double[] prev_V = new double[nS];
                for (int g = 0; g < nS; g++)
                {
                    prev_V[g] = V[g];
                }
                double diff = 0;
                for (int i = 0; i < nS; i++)
                {
                    V[i] = 0.0; // initiate to zero
                    int policyA = policy[i];
                    //trans_prob p = probT[policyA + i * nA];
                    var prob = P[policyA];
                    var rew = R[policyA];
                    double immed_reward = 0;
                    foreach (var item in prob)
                    {
                        if (item.Key.First == states[i])
                        {
                            foreach (var r in rew)
                            {
                                if (r.Key.First == item.Key.First && r.Key.Second == item.Key.Second)
                                {
                                    immed_reward = rew[r.Key];
                                }
                            }
                            var pair = item.Key;
                            var pro = item.Value;
                            V[i] += pro * (immed_reward + gamma * prev_V[states.FindIndex(a => a.ID == pair.Second.ID)]);
                        }
                    }
                    diff += Math.Abs(prev_V[i] - V[i]);
                }
                if (diff < eps)
                {
                    break;
                }
            }
            return V;
        }

        public void solveMDP()
        {
            // Creation of MDP states
            var mdpStates = createMDPStates();

            // Create action space for each states 
            createMDPActions(ref mdpStates);


            int itr = 50;
            double gamma = 0.9;
            double xr = 0.0;
            double xy = 0.0;
            for (int i = 0; i < itr; i++)
            {
                // create transition probability matrix
                var P = createTransitionProbability(mdpStates);

                // Create reward function matrix
                var R = createReward(mdpStates);

                // Find optimal policy since, S, A, P, R are created
                var x = ValueIteration(mdpStates, P, R, gamma);
                xr += x;
                //V = valueItrn(mdpStates, P, R, gamma, V);
                var y = PolicyIteration(mdpStates, P, R, gamma);
                xy += y;
            }

            Console.WriteLine(" Average reward for gamma: {0}, vi :{1}, pi :{2}, v_itr_avg:{3}, p_itr_avg:{4}"
                , gamma, xr / itr, xy / itr,((double)valueItrCount/(double)itr),((double)policyItrCount/(double)itr));

            //for (double gamma = 0.1; gamma < 1.0; gamma+=0.1)
            //{
            //    double xr = 0.0;
            //    double xy = 0.0;
            //    for (int i = 0; i < 200; i++)
            //    {
            //        // Find optimal policy since, S, A, P, R are created
            //        var x = ValueIteration(mdpStates, P, R, gamma);
            //        xr += x;
            //        //V = valueItrn(mdpStates, P, R, gamma, V);
            //        var y = PolicyIteration(mdpStates, P, R, gamma);
            //        xy += y;
            //    }
            //    Console.WriteLine(" Average reward for gamma: {0}, vi :{1}, pi :{2}", gamma, xr/200, xy/200);

            //}

            //Console.ReadLine();

        }
    }
}
